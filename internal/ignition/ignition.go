package ignition

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/coreos/ignition/v2/config/merge"
	config_31 "github.com/coreos/ignition/v2/config/v3_1"
	config_latest "github.com/coreos/ignition/v2/config/v3_2"
	config_latest_trans "github.com/coreos/ignition/v2/config/v3_2/translate"
	config_latest_types "github.com/coreos/ignition/v2/config/v3_2/types"
	"github.com/coreos/vcontext/report"
	"github.com/go-openapi/swag"
	"github.com/openshift/assisted-service/internal/common"
	"github.com/openshift/assisted-service/internal/host/hostutil"
	"github.com/openshift/assisted-service/models"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

// ParseToLatest takes the Ignition config and tries to parse it as v3.2 and if that fails,
// as v3.1. This is in order to support the latest possible Ignition as well as to preserve
// backwards-compatibility with OCP 4.6 that supports only Ignition up to v3.1
func ParseToLatest(content []byte) (*config_latest_types.Config, error) {
	config, _, err := config_latest.Parse(content)
	if err != nil {
		// TODO(deprecate-ignition-3.1.0)
		// We always want to work with the object of the type v3.2 but carry a value of v3.1 inside.
		// For this reason we are translating the config to v3.2 and manually override the Version.
		configBackwards, _, err := config_31.Parse(content)
		if err != nil {
			return nil, errors.Errorf("error parsing ignition: %v", err)
		}
		config = config_latest_trans.Translate(configBackwards)
		config.Ignition.Version = "3.1.0"
	}
	return &config, nil
}

func parseIgnitionFile(path string) (*config_latest_types.Config, error) {
	configBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Errorf("error reading file %s: %v", path, err)
	}
	return ParseToLatest(configBytes)
}

// writeIgnitionFile writes an ignition config to a given path on disk
func writeIgnitionFile(path string, config *config_latest_types.Config) error {
	updatedBytes, err := json.Marshal(config)
	if err != nil {
		return err
	}

	err = os.WriteFile(path, updatedBytes, 0600)
	if err != nil {
		return errors.Wrapf(err, "error writing file %s", path)
	}

	return nil
}

func setFileInIgnition(config *config_latest_types.Config, filePath string, fileContents string, appendContent bool, mode int, overwrite bool) {
	rootUser := "root"
	file := config_latest_types.File{
		Node: config_latest_types.Node{
			Path:      filePath,
			Overwrite: &overwrite,
			Group:     config_latest_types.NodeGroup{},
			User:      config_latest_types.NodeUser{Name: &rootUser},
		},
		FileEmbedded1: config_latest_types.FileEmbedded1{
			Append: []config_latest_types.Resource{},
			Contents: config_latest_types.Resource{
				Source: &fileContents,
			},
			Mode: &mode,
		},
	}
	if appendContent {
		file.FileEmbedded1.Append = []config_latest_types.Resource{
			{
				Source: &fileContents,
			},
		}
		file.FileEmbedded1.Contents = config_latest_types.Resource{}
	}
	config.Storage.Files = append(config.Storage.Files, file)
}

//lint:ignore U1000 Ignore unused function
//nolint:unused,deadcode
func setUnitInIgnition(config *config_latest_types.Config, contents, name string, enabled bool) {
	newUnit := config_latest_types.Unit{
		Contents: swag.String(contents),
		Name:     name,
		Enabled:  swag.Bool(enabled),
	}
	config.Systemd.Units = append(config.Systemd.Units, newUnit)
}

func setCACertInIgnition(role models.HostRole, path string, workDir string, caCertFile string) error {
	config, err := parseIgnitionFile(path)
	if err != nil {
		return err
	}

	var caCertData []byte
	caCertData, err = os.ReadFile(caCertFile)
	if err != nil {
		return err
	}

	setFileInIgnition(config, common.HostCACertPath, fmt.Sprintf("data:,%s", url.PathEscape(string(caCertData))), false, 420, false)

	fileName := fmt.Sprintf("%s.ign", role)
	err = writeIgnitionFile(filepath.Join(workDir, fileName), config)
	if err != nil {
		return err
	}

	return nil
}

func HasCACertInIgnition(contents string) bool {
	config, err := ParseToLatest([]byte(contents))
	if err != nil {
		return false
	}
	return len(config.Ignition.Security.TLS.CertificateAuthorities) > 0
}

func writeHostFiles(hosts []*models.Host, baseFile string, workDir string) error {
	g := new(errgroup.Group)
	for i := range hosts {
		host := hosts[i]
		g.Go(func() error {
			config, err := parseIgnitionFile(filepath.Join(workDir, baseFile))
			if err != nil {
				return err
			}

			hostname, err := hostutil.GetCurrentHostName(host)
			if err != nil {
				return errors.Wrapf(err, "failed to get hostname for host %s", host.ID)
			}

			setFileInIgnition(config, "/etc/hostname", fmt.Sprintf("data:,%s", hostname), false, 420, true)

			configBytes, err := json.Marshal(config)
			if err != nil {
				return err
			}

			if host.IgnitionConfigOverrides != "" {
				merged, mergeErr := MergeIgnitionConfig(configBytes, []byte(host.IgnitionConfigOverrides))
				if mergeErr != nil {
					return errors.Wrapf(mergeErr, "failed to apply ignition config overrides for host %s", host.ID)
				}
				configBytes = []byte(merged)
			}

			err = os.WriteFile(filepath.Join(workDir, hostutil.IgnitionFileName(host)), configBytes, 0600)
			if err != nil {
				return errors.Wrapf(err, "failed to write ignition for host %s", host.ID)
			}

			return nil
		})
	}

	return g.Wait()
}

// createHostIgnitions builds an ignition file for each host in the cluster based on the generated <role>.ign file
func (g *installerGenerator) createHostIgnitions() error {
	masters, workers := sortHosts(g.cluster.Hosts)

	err := writeHostFiles(masters, masterIgn, g.workDir)
	if err != nil {
		return errors.Wrapf(err, "error writing master host ignition files")
	}

	err = writeHostFiles(workers, workerIgn, g.workDir)
	if err != nil {
		return errors.Wrapf(err, "error writing worker host ignition files")
	}

	return nil
}

func MergeIgnitionConfig(base []byte, overrides []byte) (string, error) {
	baseConfig, err := ParseToLatest(base)
	if err != nil {
		return "", err
	}

	overrideConfig, err := ParseToLatest(overrides)
	if err != nil {
		return "", err
	}

	mergeResult, _ := merge.MergeStructTranscribe(*baseConfig, *overrideConfig)
	res, err := json.Marshal(mergeResult)
	if err != nil {
		return "", err
	}

	// TODO(deprecate-ignition-3.1.0)
	// We want to validate if users do not try to override with putting features of 3.2.0 into
	// ignition manifest of 3.1.0. Because the merger function from ignition package is
	// version-agnostic and returns only interface{}, we need to hack our way into accessing
	// the content as a regular Config
	var report report.Report
	switch v := mergeResult.(type) {
	case config_latest_types.Config:
		if v.Ignition.Version == "3.1.0" {
			_, report, err = config_31.Parse(res)
		} else {
			_, report, err = config_latest.Parse(res)
		}
	default:
		return "", errors.Errorf("merged ignition config has invalid type: %T", v)
	}
	if err != nil {
		return "", err
	}
	if report.IsFatal() {
		return "", errors.Errorf("merged ignition config is invalid: %s", report.String())
	}

	return string(res), nil
}
