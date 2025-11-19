package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/moby/policy-helpers/types"
)

type SignatureInfoFormatter types.SignatureInfo

func (f SignatureInfoFormatter) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			// Detailed format with tabwriter
			tw := tabwriter.NewWriter(s, 0, 0, 2, ' ', 0)
			defer tw.Flush()

			if f.IsDHI {
				fmt.Fprintln(tw, "Image Type:\tDocker Hardened Image (DHI)")
			}

			if f.Signer != nil {
				// Certificate Summary Section
				fmt.Fprintf(tw, "Certificate Issuer:\t%s\n", f.Signer.CertificateIssuer)
				fmt.Fprintf(tw, "Subject Alternative Name:\t%s\n", f.Signer.SubjectAlternativeName)
				fmt.Fprintln(tw)

				// Extensions Section
				if f.Signer.Issuer != "" {
					fmt.Fprintf(tw, "Signer Issuer:\t%s\n", f.Signer.Issuer)
				}
				if f.Signer.BuildSignerURI != "" {
					fmt.Fprintf(tw, "Build Signer URI:\t%s\n", f.Signer.BuildSignerURI)
				}
				if f.Signer.BuildSignerDigest != "" {
					fmt.Fprintf(tw, "Build Signer Digest:\t%s\n", f.Signer.BuildSignerDigest)
				}
				if f.Signer.RunnerEnvironment != "" {
					fmt.Fprintf(tw, "Runner Environment:\t%s\n", f.Signer.RunnerEnvironment)
				}
				if f.Signer.SourceRepositoryURI != "" {
					fmt.Fprintf(tw, "Source Repository URI:\t%s\n", f.Signer.SourceRepositoryURI)
				}
				if f.Signer.SourceRepositoryDigest != "" {
					fmt.Fprintf(tw, "Source Repository Digest:\t%s\n", f.Signer.SourceRepositoryDigest)
				}
				if f.Signer.SourceRepositoryRef != "" {
					fmt.Fprintf(tw, "Source Repository Ref:\t%s\n", f.Signer.SourceRepositoryRef)
				}
				if f.Signer.SourceRepositoryIdentifier != "" {
					fmt.Fprintf(tw, "Source Repository Identifier:\t%s\n", f.Signer.SourceRepositoryIdentifier)
				}
				if f.Signer.SourceRepositoryOwnerURI != "" {
					fmt.Fprintf(tw, "Source Repository Owner URI:\t%s\n", f.Signer.SourceRepositoryOwnerURI)
				}
				if f.Signer.SourceRepositoryOwnerIdentifier != "" {
					fmt.Fprintf(tw, "Source Repository Owner ID:\t%s\n", f.Signer.SourceRepositoryOwnerIdentifier)
				}
				if f.Signer.BuildConfigURI != "" {
					fmt.Fprintf(tw, "Build Config URI:\t%s\n", f.Signer.BuildConfigURI)
				}
				if f.Signer.BuildConfigDigest != "" {
					fmt.Fprintf(tw, "Build Config Digest:\t%s\n", f.Signer.BuildConfigDigest)
				}
				if f.Signer.BuildTrigger != "" {
					fmt.Fprintf(tw, "Build Trigger:\t%s\n", f.Signer.BuildTrigger)
				}
				if f.Signer.RunInvocationURI != "" {
					fmt.Fprintf(tw, "Run Invocation URI:\t%s\n", f.Signer.RunInvocationURI)
				}
				if f.Signer.SourceRepositoryVisibilityAtSigning != "" {
					fmt.Fprintf(tw, "Source Repository Visibility:\t%s\n", f.Signer.SourceRepositoryVisibilityAtSigning)
				}

				// Deprecated GitHub Workflow fields
				if f.Signer.GithubWorkflowTrigger != "" {
					fmt.Fprintf(tw, "GitHub Workflow Trigger:\t%s\t(deprecated)\n", f.Signer.GithubWorkflowTrigger)
				}
				if f.Signer.GithubWorkflowSHA != "" {
					fmt.Fprintf(tw, "GitHub Workflow SHA:\t%s\t(deprecated)\n", f.Signer.GithubWorkflowSHA)
				}
				if f.Signer.GithubWorkflowName != "" {
					fmt.Fprintf(tw, "GitHub Workflow Name:\t%s\t(deprecated)\n", f.Signer.GithubWorkflowName)
				}
				if f.Signer.GithubWorkflowRepository != "" {
					fmt.Fprintf(tw, "GitHub Workflow Repository:\t%s\t(deprecated)\n", f.Signer.GithubWorkflowRepository)
				}
				if f.Signer.GithubWorkflowRef != "" {
					fmt.Fprintf(tw, "GitHub Workflow Ref:\t%s\t(deprecated)\n", f.Signer.GithubWorkflowRef)
				}
				fmt.Fprintln(tw)
			}

			if f.DockerReference != "" {
				fmt.Fprintf(tw, "Docker Reference:\t%s\n", f.DockerReference)
				fmt.Fprintln(tw)
			}

			// Timestamps Section
			if len(f.Timestamps) > 0 {
				fmt.Fprintln(tw, "--- Timestamp Verification Results ---")
				fmt.Fprintln(tw, "TYPE\tURI\tTIMESTAMP")
				for _, ts := range f.Timestamps {
					fmt.Fprintf(tw, "%s\t%s\t%s\n",
						ts.Type,
						ts.URI,
						ts.Timestamp.Format("2006-01-02 15:04:05 MST"))
				}
				fmt.Fprintln(tw)
			}

			if f.TrustRootStatus.Error != "" {
				fmt.Fprintf(s, "Warning: Latest trust root could not be fetched: %s. Possible connection issue or offline mode used.\n", f.TrustRootStatus.Error)
				if f.TrustRootStatus.LastUpdated != nil {
					fmt.Fprintf(s, "Using trust root last updated at: %s\n", f.TrustRootStatus.LastUpdated.Format("2006-01-02 15:04:05 MST"))
				}
			}
		} else {
			fmt.Fprintf(s, "%s,SAN=%s",
				f.Signer.CertificateIssuer, f.Signer.SubjectAlternativeName)
		}
	case 's':
		fmt.Fprintf(s, "%s (%s)", f.Signer.SubjectAlternativeName, f.Signer.CertificateIssuer)
	default:
		fmt.Fprintf(s, "%%!%c(SignatureInfoFormatter)", verb)
	}
}
