/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certificaterequest

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/ctl"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
)

var (
	long = templates.LongDesc(i18n.T(`
Create a new certificatebundle in a ConfigMap resource, by generating a trust bundle based on certificate sources.`))

	example = templates.Examples(i18n.T(build.WithTemplate(`
# Create a certificatebundle with the name 'my-bundle'
{{.BuildName}} create certificatebundle my-bundle --from-configmap-file my-certificate.yaml --from-secret-file my-secret.yaml 

# Create a certificatebundle with the name 'my-bundle', and saves the bundle to my-bundle.yaml configmap
{{.BuildName}} create certificatebundle my-bundle --from-configmap-file my-certificate.yaml --from-secret-file my-secret.yaml --output-file my-bundle.yaml

`)))
)

var (
	// Dedicated scheme used by the ctl tool that has the internal cert-manager types,
	// and their conversion functions registered
	scheme = ctl.Scheme
)

// Options is a struct to support create certificatebundle command
// TODO : ADD MULTIPLE SOURCE FILES IN THE COMMAND?
type Options struct {
	// Name of file that the generated private key will be stored in
	// If not specified, the private key will be written to <NameOfCR>.key
	ConfigMapName string
	// Name of file that the generated x509 certificate will be stored in if --fetch-certificate flag is set
	// If not specified, the private key will be written to <NameOfCR>.crt
	SecretName string
	// Path to a file containing a Certificate resource used as a template
	// when generating the certificatebundle resource
	// Required
	Namespace string
	// Output file name for saving bundle to a local file
	OutputFilename string

	genericclioptions.IOStreams
	*factory.Factory
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdCreateCR returns a cobra command for create certificatebundle
func NewCmdCreateCR(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
	o := NewOptions(ioStreams)

	cmd := &cobra.Command{
		Use:     "certificatebundle",
		Aliases: []string{"cr"},
		Short:   "Create a cert-manager certificatebundle resource, using a Certificate resource as a template",
		Long:    long,
		Example: example,
		//ValidArgsFunction: factory.validArgsListNamespaces(ctx, &o.Factory),
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(o.Validate(args))
			cmdutil.CheckErr(o.Run(ctx, args))
		},
	}
	cmd.Flags().StringVar(&o.ConfigMapName, "from-configmap", o.ConfigMapName,
		"Path to a file containing a Certificate resource used as a template when generating the certificatebundle resource")
	cmd.Flags().StringVar(&o.SecretName, "from-secret", o.SecretName,
		"Name of file that the generated private key will be written to")
	cmd.Flags().StringVar(&o.Namespace, "namespace", o.Namespace,
		"Name of the file the certificate is to be stored in")
	cmd.Flags().StringVar(&o.OutputFilename, "output-file", o.OutputFilename,
		"Name of the file the certificate is to be stored in")
	o.Factory = factory.New(ctx, cmd)

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(args []string) error {
	if len(args) < 1 {
		return errors.New("the name of the certificatebundle to be created has to be provided as argument")
	}
	if len(args) > 1 {
		return errors.New("only one argument can be passed in: the name of the certificatebundle")
	}

	if o.ConfigMapName == "" && o.SecretName == "" {
		return errors.New("the path to a YAML manifest of a Certificate resource cannot be empty, please specify by using --from-certificate-file flag")
	}

	return nil
}

// Run executes create certificatebundle command
func (o *Options) Run(ctx context.Context, args []string) error {
	builder := new(resource.Builder)

	// Read file as internal API version
	r := builder.
		WithScheme(scheme, schema.GroupVersion{Group: cmapi.SchemeGroupVersion.Group, Version: runtime.APIVersionInternal}).
		LocalParam(true).ContinueOnError().
		NamespaceParam(o.Namespace).DefaultNamespace().
		FilenameParam(o.EnforceNamespace, &resource.FilenameOptions{Filenames: []string{o.InputFilename}}).Flatten().Do()

	if err := r.Err(); err != nil {
		return err
	}

	singleItemImplied := false
	infos, err := r.IntoSingleItemImplied(&singleItemImplied).Infos()
	if err != nil {
		return err
	}

	// Ensure only one object per command
	if len(infos) == 0 {
		return fmt.Errorf("no objects found in manifest file %q. Expected one Certificate object", o.InputFilename)
	}
	if len(infos) > 1 {
		return fmt.Errorf("multiple objects found in manifest file %q. Expected only one Certificate object", o.InputFilename)
	}
	info := infos[0]
	// Convert to v1 because that version is needed for functions that follow
	crtObj, err := scheme.ConvertToVersion(info.Object, cmapi.SchemeGroupVersion)
	if err != nil {
		return fmt.Errorf("failed to convert object into version v1: %w", err)
	}

	// Cast Object into Certificate
	crt, ok := crtObj.(*cmapi.Certificate)
	if !ok {
		return errors.New("decoded object is not a v1 Certificate")
	}

	crt = crt.DeepCopy()
	if crt.Spec.PrivateKey == nil {
		crt.Spec.PrivateKey = &cmapi.CertificatePrivateKey{}
	}

	signer, err := pki.GeneratePrivateKeyForCertificate(crt)
	if err != nil {
		return fmt.Errorf("error when generating new private key for certificatebundle: %w", err)
	}

	keyData, err := pki.EncodePrivateKey(signer, crt.Spec.PrivateKey.Encoding)
	if err != nil {
		return fmt.Errorf("failed to encode new private key for certificatebundle: %w", err)
	}

	crName := args[0]

	// Storing private key to file
	keyFileName := crName + ".key"
	if o.KeyFilename != "" {
		keyFileName = o.KeyFilename
	}
	if err := os.WriteFile(keyFileName, keyData, 0600); err != nil {
		return fmt.Errorf("error when writing private key to file: %w", err)
	}
	fmt.Fprintf(o.ErrOut, "Private key written to file %s\n", keyFileName)

	// Build certificatebundle with name as specified by argument
	req, err := buildcertificatebundle(crt, keyData, crName)
	if err != nil {
		return fmt.Errorf("error when building certificatebundle: %w", err)
	}

	ns := crt.Namespace
	if ns == "" {
		ns = o.Namespace
	}
	req, err = o.CMClient.CertmanagerV1().certificatebundles(ns).Create(ctx, req, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error creating certificatebundle: %w", err)
	}
	fmt.Fprintf(o.ErrOut, "certificatebundle %s has been created in namespace %s\n", req.Name, req.Namespace)

	if o.FetchCert {
		fmt.Fprintf(o.ErrOut, "certificatebundle %v in namespace %v has not been signed yet. Wait until it is signed...\n",
			req.Name, req.Namespace)
		err = wait.PollUntilContextTimeout(ctx, time.Second, o.Timeout, false, func(ctx context.Context) (done bool, err error) {
			req, err = o.CMClient.CertmanagerV1().certificatebundles(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			return apiutil.certificatebundleHasCondition(req, cmapi.certificatebundleCondition{
				Type:   cmapi.certificatebundleConditionReady,
				Status: cmmeta.ConditionTrue,
			}) && len(req.Status.Certificate) > 0, nil
		})
		if err != nil {
			return fmt.Errorf("error when waiting for certificatebundle to be signed: %w", err)
		}
		fmt.Fprintf(o.ErrOut, "certificatebundle %v in namespace %v has been signed\n", req.Name, req.Namespace)

		// Fetch x509 certificate and store to file
		actualCertFileName := req.Name + ".crt"
		if o.CertFileName != "" {
			actualCertFileName = o.CertFileName
		}
		err = fetchCertificateFromCR(req, actualCertFileName)
		if err != nil {
			return fmt.Errorf("error when writing certificate to file: %w", err)
		}
		fmt.Fprintf(o.ErrOut, "Certificate written to file %s\n", actualCertFileName)
	}

	return nil
}

// Builds a certificatebundle
func buildcertificatebundle(crt *cmapi.Certificate, pk []byte, crName string) (*cmapi.certificatebundle, error) {
	csrPEM, err := generateCSR(crt, pk)
	if err != nil {
		return nil, err
	}

	cr := &cmapi.certificatebundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:        crName,
			Annotations: crt.Annotations,
			Labels:      crt.Labels,
		},
		Spec: cmapi.certificatebundleSpec{
			Request:   csrPEM,
			Duration:  crt.Spec.Duration,
			IssuerRef: crt.Spec.IssuerRef,
			IsCA:      crt.Spec.IsCA,
			Usages:    crt.Spec.Usages,
		},
	}

	return cr, nil
}

func generateCSR(crt *cmapi.Certificate, pk []byte) ([]byte, error) {
	csr, err := pki.GenerateCSR(crt)
	if err != nil {
		return nil, err
	}

	signer, err := pki.DecodePrivateKeyBytes(pk)
	if err != nil {
		return nil, err
	}

	csrDER, err := pki.EncodeCSR(csr, signer)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	})

	return csrPEM, nil
}

// fetchCertificateFromCR fetches the x509 certificate from a CR and stores the
// certificate in file specified by certFilename. Assumes CR is ready,
// otherwise returns error.
func fetchCertificateFromCR(req *cmapi.certificatebundle, certFileName string) error {
	// If CR not ready yet, error
	if !apiutil.certificatebundleHasCondition(req, cmapi.certificatebundleCondition{
		Type:   cmapi.certificatebundleConditionReady,
		Status: cmmeta.ConditionTrue,
	}) || len(req.Status.Certificate) == 0 {
		return errors.New("certificatebundle is not ready yet, unable to fetch certificate")
	}

	// Store certificate to file
	err := os.WriteFile(certFileName, req.Status.Certificate, 0600)
	if err != nil {
		return fmt.Errorf("error when writing certificate to file: %w", err)
	}

	return nil
}
