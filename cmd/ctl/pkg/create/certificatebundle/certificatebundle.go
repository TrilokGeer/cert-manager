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

package certificatebundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/build"
	"github.com/cert-manager/cert-manager/cmd/ctl/pkg/factory"
	"github.com/cert-manager/cert-manager/pkg/ctl"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
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
	// Required
	OldCACert string

	// Name of file that the generated private key will be stored in
	// If not specified, the private key will be written to <NameOfCR>.key
	// Required
	NewCACert string
	/*
		// configmap key selector
		CMKeySelector string
		// Name of file that the generated x509 certificate will be stored in if --fetch-certificate flag is set
		// If not specified, the private key will be written to <NameOfCR>.crt
		SecretName string

		// Secret key selector
		SecretKeySelector string
	*/
	// Path to a file containing a Certificate resource used as a template
	// when generating the certificatebundle resource
	// Required
	// Namespace string

	// Output file name for saving bundle to a local file
	Name string

	// Output as trust bundle
	// or as config map
	OutputAs string

	genericclioptions.IOStreams

	*factory.Factory
}

// NewOptions returns initialized Options
func NewOptions(ioStreams genericclioptions.IOStreams) *Options {
	return &Options{
		IOStreams: ioStreams,
	}
}

// NewCmdCreateCB returns a cobra command for create certificatebundle
func NewCmdCreateCB(ctx context.Context, ioStreams genericclioptions.IOStreams) *cobra.Command {
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
	cmd.Flags().StringVar(&o.OldCACert, "old-ca-cert", o.OldCACert,
		"Path to a file containing a Certificate resource used as a template when generating the certificatebundle resource")
	cmd.Flags().StringVar(&o.NewCACert, "new-ca-cert", o.NewCACert,
		"Name of file that the generated private key will be written to")
	/*
		cmd.Flags().StringVar(&o.Namespace, "namespace", o.Namespace,
			"Name of the file the certificate is to be stored in")*/
	cmd.Flags().StringVar(&o.Name, "name", o.Name,
		"Name of the file the certificate is to be stored in")
	cmd.Flags().StringVar(&o.OutputAs, "output-as", o.OutputAs,
		"Name of the file the certificate is to be stored in")
	o.Factory = factory.New(ctx, cmd)

	return cmd
}

// Validate validates the provided options
func (o *Options) Validate(args []string) error {
	// TBD

	if o.Name == "" {
		return errors.New("name field is required to create output by specified name")
	}

	return nil
}

func (o *Options) BundleToConfigmap(oldcasecret, newcasecret *v1.Secret) (*v1.ConfigMap, error) {

	var cadata string
	var bundle []string
	var packedBundle string

	cadata = string(oldcasecret.Data["tls.crt"])
	sanitizedcadata, err := ValidateAndSanitizePEMBundle([]byte(cadata))
	if err != nil {
		fmt.Errorf("Failed to validate and sanitize pem data for old ca")
		return nil, nil
	}
	bundle = append(bundle, string(sanitizedcadata))

	cadata = string(newcasecret.Data["tls.crt"])
	sanitizedcadata, err = ValidateAndSanitizePEMBundle([]byte(cadata))
	if err != nil {
		fmt.Errorf("Failed to validate and sanitize pem data for new ca")
		return nil, nil
	}
	bundle = append(bundle, string(sanitizedcadata))
	packedBundle = strings.Join(bundle, "\n") + "\n"
	var datamap = make(map[string]string, 1)
	datamap["bundle.crt"] = packedBundle
	cm := v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      o.Name,
			Namespace: o.Namespace,
		},
		Immutable:  nil,
		Data:       datamap,
		BinaryData: nil,
	}
	return &cm, nil
}

// Run executes create certificatebundle command
func (o *Options) Run(ctx context.Context, args []string) error {

	oldcacertificate, err := o.CMClient.CertmanagerV1().Certificates(o.Namespace).Get(ctx, o.OldCACert, metav1.GetOptions{})
	if err != nil {
		fmt.Errorf("Failed to retrieve certificate object [%s] with error [%v]", o.OldCACert, err.Error())
		return err
	}
	if oldcacertificate.Spec.IsCA == false {
		fmt.Errorf("Retrieved certificate object [%s] is not CA certificate", o.OldCACert)
		return err
	}
	if oldcacertificate.Status.Conditions[0].Type != "Ready" {
		fmt.Errorf("Retrieved certificate object [%s] is not ready", o.OldCACert)
		return err
	}
	if oldcacertificate.Status.Conditions[0].Status != "True" {
		fmt.Errorf("Retrieved certificate object [%s] ready status is false", o.OldCACert)
		return err
	}

	newcacertificate, err := o.CMClient.CertmanagerV1().Certificates(o.Namespace).Get(ctx, o.NewCACert, metav1.GetOptions{})
	if err != nil {
		fmt.Errorf("Failed to retrieve certificate object [%s] with error [%v]", o.NewCACert, err.Error())
		return err
	}
	if newcacertificate.Spec.IsCA == false {
		fmt.Errorf("Retrieved certificate object [%s] is not CA certificate", o.NewCACert)
		return err
	}
	if newcacertificate.Status.Conditions[0].Type != "Ready" {
		fmt.Errorf("Retrieved certificate object [%s] is not ready", o.OldCACert)
		return err
	}
	if newcacertificate.Status.Conditions[0].Status != "True" {
		fmt.Errorf("Retrieved certificate object [%s] ready status is false", o.OldCACert)
		return err
	}
	// retrieve secrets from old ca certificate
	oldcasecret, err := o.KubeClient.CoreV1().Secrets(o.Namespace).Get(ctx, oldcacertificate.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		fmt.Errorf("Failed to retrieve secret [%s] with error [%v]", oldcacertificate.Spec.SecretName, err)
		return err
	}
	fmt.Printf("Retrieved old ca secret ======")
	jsondata, _ := json.Marshal(oldcasecret)
	fmt.Print("[%v]", jsondata)
	fmt.Printf("Retrieved old ca secret ends======")

	newcasecret, err := o.KubeClient.CoreV1().Secrets(o.Namespace).Get(ctx, newcacertificate.Spec.SecretName, metav1.GetOptions{})
	if err != nil {
		fmt.Errorf("Failed to retrieve secret [%s] with error [%v]", newcacertificate.Spec.SecretName, err)
		return err
	}
	fmt.Printf("Retrieved new ca secret ======")
	jsondata, _ = json.Marshal(newcasecret)
	fmt.Print("[%v]", jsondata)
	fmt.Printf("Retrieved new ca secret ends======")

	switch o.OutputAs {
	case "configmap":
		configmap, err := o.BundleToConfigmap(oldcasecret, newcasecret)
		if err != nil {
			fmt.Errorf("Failed to build configmap with error [%v]", err)
			return err
		}
		_, err = o.KubeClient.CoreV1().ConfigMaps(o.Namespace).Create(ctx, configmap, metav1.CreateOptions{})
		if err != nil {
			fmt.Errorf("Create config map failed with error [%v]", err)
			return err
		}
	case "trustbundle":
		//TBD
	}
	return nil
}
