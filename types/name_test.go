package types

import (
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/stretchr/testify/require"
)

func TestSignatureInfo_Name(t *testing.T) {
	tests := []struct {
		name string
		in   SignatureInfo
		want string
	}{
		{
			name: "dhi-basic",
			in: SignatureInfo{
				Kind:            KindDockerHardenedImage,
				IsDHI:           true,
				DockerReference: "docker.io/dhi/golang",
			},
			want: "Docker Hardened Image (docker.io/dhi/golang)",
		},

		{
			name: "github-builder-main-branch",
			in: SignatureInfo{
				Kind:          KindDockerGithubBuilder,
				Timestamps:    ts(),
				SignatureType: SignatureBundleV03,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: githubBuilderURI + "build.yml",
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						BuildTrigger:        "workflow_dispatch",
						RunnerEnvironment:   "github-hosted",
						SourceRepositoryURI: "https://github.com/docker/buildx",
						SourceRepositoryRef: "refs/heads/main",
						BuildSignerURI:      githubBuilderURI + "build.yml",
					},
				},
			},
			want: "Docker GitHub Builder (docker/buildx@main)",
		},

		{
			name: "github-builder-experimental",
			in: SignatureInfo{
				Kind:          KindDockerGithubBuilder,
				Timestamps:    ts(),
				SignatureType: SignatureBundleV03,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: githubBuilderURIExperimental + "exp.yml",
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						BuildTrigger:        "workflow_dispatch",
						RunnerEnvironment:   "github-hosted",
						SourceRepositoryURI: "https://github.com/docker/buildx",
						SourceRepositoryRef: "refs/tags/v1.0.0",
						BuildSignerURI:      githubBuilderURIExperimental + "exp.yml",
					},
				},
			},
			want: "Docker GitHub Builder Experimental (docker/buildx@v1.0.0)",
		},

		{
			name: "github-builder-hashrecord-invalid",
			in: SignatureInfo{
				Kind:          KindSelfSigned,
				Timestamps:    ts(),
				SignatureType: SignatureSimpleSigningV1,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: githubBuilderURI + "build.yml",
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						BuildTrigger:        "workflow_dispatch",
						RunnerEnvironment:   "github-hosted",
						SourceRepositoryURI: "https://github.com/docker/buildx",
						SourceRepositoryRef: "refs/heads/main",
						BuildSignerURI:      githubBuilderURI + "build.yml",
					},
				},
			},
			want: "Self-Signed",
		},

		{
			name: "github-self-signed",
			in: SignatureInfo{
				Kind: KindSelfSignedGithubRepo,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: "https://github.com/foo/bar/.github/workflows/ci.yml",
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						RunnerEnvironment:   "github-hosted",
						SourceRepositoryURI: "https://github.com/foo/bar",
						BuildSignerURI:      "https://github.com/foo/bar/.github/workflows/ci.yml",
					},
				},
			},
			want: "GitHub Self-Signed (foo/bar)",
		},

		{
			name: "self-signed-google-local",
			in: SignatureInfo{
				Kind: KindSelfSigned,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: "user@gmail.com",
					Extensions: certificate.Extensions{
						Issuer:            googleUserIssuer,
						RunnerEnvironment: "my-desktop",
					},
				},
			},
			want: "Self-Signed Local (Google: user@gmail.com)",
		},

		{
			name: "self-signed-github-oauth-hosted",
			in: SignatureInfo{
				Kind: KindSelfSigned,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: "octocat",
					Extensions: certificate.Extensions{
						Issuer:            githubUserIssuer,
						RunnerEnvironment: "github-hosted",
					},
				},
			},
			want: "Self-Signed (GitHub: octocat)",
		},

		{
			name: "neg-no-signer",
			in: SignatureInfo{
				Kind: KindUntrusted,
			},
			want: "Untrusted",
		},

		{
			name: "neg-wrong-cert-issuer",
			in: SignatureInfo{
				Kind: KindUntrusted,
				Signer: &certificate.Summary{
					CertificateIssuer: "BAD",
				},
			},
			want: "Untrusted",
		},

		{
			name: "neg-missing-timestamps-builder",
			in: SignatureInfo{
				Kind: KindSelfSigned,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: githubBuilderURI,
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						BuildTrigger:        "workflow_dispatch",
						RunnerEnvironment:   "github-hosted",
						SourceRepositoryURI: "https://github.com/foo/bar",
						SourceRepositoryRef: "refs/heads/main",
						BuildSignerURI:      githubBuilderURI,
					},
				},
			},
			want: "Self-Signed",
		},

		{
			name: "different-trigger",
			in: SignatureInfo{
				Kind:          KindDockerGithubBuilder,
				Timestamps:    ts(),
				SignatureType: SignatureBundleV03,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: githubBuilderURI,
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						BuildTrigger:        "push",
						RunnerEnvironment:   "github-hosted",
						SourceRepositoryURI: "https://github.com/foo/bar",
						SourceRepositoryRef: "refs/heads/main",
						BuildSignerURI:      githubBuilderURI,
					},
				},
			},
			want: "Docker GitHub Builder (foo/bar@main)",
		},

		{
			name: "neg-wrong-runner-env",
			in: SignatureInfo{
				Kind:       KindSelfSigned,
				Timestamps: ts(),
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: githubBuilderURI,
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						BuildTrigger:        "workflow_dispatch",
						RunnerEnvironment:   "self-hosted",
						SourceRepositoryURI: "https://github.com/foo/bar",
						SourceRepositoryRef: "refs/heads/main",
						BuildSignerURI:      githubBuilderURI,
					},
				},
			},
			want: "Self-Signed Local",
		},

		{
			name: "neg-wrong-builder-uri",
			in: SignatureInfo{
				Kind:       KindSelfSigned,
				Timestamps: ts(),
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: "https://example.com/x",
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						BuildTrigger:        "workflow_dispatch",
						RunnerEnvironment:   "github-hosted",
						SourceRepositoryURI: "https://github.com/foo/bar",
						SourceRepositoryRef: "refs/heads/main",
						BuildSignerURI:      "https://example.com/x",
					},
				},
			},
			want: "Self-Signed",
		},

		{
			name: "github-builder-tag-ref",
			in: SignatureInfo{
				Kind:          KindDockerGithubBuilder,
				Timestamps:    ts(),
				SignatureType: SignatureBundleV03,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: githubBuilderURI + "release.yml",
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						BuildTrigger:        "workflow_dispatch",
						RunnerEnvironment:   "github-hosted",
						SourceRepositoryURI: "https://github.com/acme/rocket",
						SourceRepositoryRef: "refs/tags/v9.9.9",
						BuildSignerURI:      githubBuilderURI + "release.yml",
					},
				},
			},
			want: "Docker GitHub Builder (acme/rocket@v9.9.9)",
		},

		{
			name: "self-signed-email-google",
			in: SignatureInfo{
				Kind: KindSelfSigned,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: "user@gmail.com",
					Extensions: certificate.Extensions{
						Issuer:            googleUserIssuer,
						RunnerEnvironment: "github-hosted",
					},
				},
			},
			want: "Self-Signed (Google: user@gmail.com)",
		},

		{
			name: "self-signed-github-oauth-local",
			in: SignatureInfo{
				Kind: KindSelfSigned,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: "octo-user",
					Extensions: certificate.Extensions{
						Issuer:            githubUserIssuer,
						RunnerEnvironment: "my-mac",
					},
				},
			},
			want: "Self-Signed Local (GitHub: octo-user)",
		},

		{
			name: "neg-github-builder-wrong-source-repo-prefix",
			in: SignatureInfo{
				Kind:       KindSelfSigned,
				Timestamps: ts(),
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: githubBuilderURI + "build.yml",
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						BuildTrigger:        "workflow_dispatch",
						RunnerEnvironment:   "github-hosted",
						SourceRepositoryURI: "https://gitlab.com/foo/bar", // wrong host
						SourceRepositoryRef: "refs/heads/main",
						BuildSignerURI:      githubBuilderURI + "build.yml",
					},
				},
			},
			want: "Self-Signed",
		},

		{
			name: "neg-github-self-signed-wrong-signer-uri-prefix",
			in: SignatureInfo{
				Kind: KindSelfSigned,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: "https://github.com/foo/bar/.github/workflows/x.yml",
					Extensions: certificate.Extensions{
						Issuer:              githubIssuer,
						RunnerEnvironment:   "github-hosted",
						SourceRepositoryURI: "https://github.com/foo/bar",
						BuildSignerURI:      "https://github.com/foo/bar/.github/workflows-typo/x.yml",
					},
				},
			},
			want: "Self-Signed",
		},

		{
			name: "neg-self-signed-google-but-runner-hosted",
			in: SignatureInfo{
				Kind: KindSelfSigned,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: "user@gmail.com",
					Extensions: certificate.Extensions{
						Issuer:            googleUserIssuer,
						RunnerEnvironment: "github-hosted",
					},
				},
			},
			want: "Self-Signed (Google: user@gmail.com)",
		},

		{
			name: "neg-self-signed-empty-san",
			in: SignatureInfo{
				Kind: KindSelfSigned,
				Signer: &certificate.Summary{
					CertificateIssuer:      sigstoreIssuer,
					SubjectAlternativeName: "",
					Extensions: certificate.Extensions{
						Issuer:            googleUserIssuer,
						RunnerEnvironment: "my-desktop",
					},
				},
			},
			want: "Self-Signed Local (Google: )",
		},

		{
			name: "corruption",
			in: SignatureInfo{
				Kind: 0,
			},
			want: "Invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.in.Kind != 0 {
				kind := tt.in.DetectKind()
				require.Equal(t, kind, tt.in.Kind)
			}
			require.Equal(t, tt.want, tt.in.Name())
		})
	}
}

func ts() []TimestampVerificationResult {
	return []TimestampVerificationResult{
		{Type: "Tlog", URI: "https://rekor.sigstore.dev", Timestamp: time.Now()},
	}
}
