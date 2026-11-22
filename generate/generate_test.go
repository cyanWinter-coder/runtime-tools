package generate_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	rfc2119 "github.com/opencontainers/runtime-tools/error"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/opencontainers/runtime-tools/specerror"
	"github.com/opencontainers/runtime-tools/validate"
	"github.com/stretchr/testify/assert"
)

// Smoke test to ensure that _at the very least_ our default configuration
// passes the validation tests. If this test fails, something is _very_ wrong
// and needs to be fixed immediately (as it will break downstreams that depend
// on us for a "sane default" and do compliance testing -- such as umoci).
func TestGenerateValid(t *testing.T) {
	plat := "linux"
	if runtime.GOOS == "windows" {
		plat = "windows"
	}

	isolations := []string{"process", "hyperv"}
	for _, isolation := range isolations {
		if plat == "linux" && isolation == "hyperv" {
			// Combination doesn't make sense.
			continue
		}

		bundle, err := os.MkdirTemp("", "TestGenerateValid_bundle")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(bundle)

		// Create our toy bundle.
		rootfsPath := filepath.Join(bundle, "rootfs")
		if err := os.Mkdir(rootfsPath, 0o755); err != nil {
			t.Fatal(err)
		}
		configPath := filepath.Join(bundle, "config.json")
		g, err := generate.New(plat)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			g.AddWindowsLayerFolders("C:\\fakelayer")
			g.AddWindowsLayerFolders("C:\\fakescratch")
			if isolation == "process" {
				// Add the Rootfs section (note: fake volume guid)
				g.SetRootPath("\\\\?\\Volume{ec84d99e-3f02-11e7-ac6c-00155d7682cf}\\")
			} else {
				// Add the Hyper-V section
				g.SetWindowsHypervUntilityVMPath("")
			}
		}
		if err := (&g).SaveToFile(configPath, generate.ExportOptions{Seccomp: false}); err != nil {
			t.Fatal(err)
		}

		// Validate the bundle.
		v, err := validate.NewValidatorFromPath(bundle, true, runtime.GOOS)
		if err != nil {
			t.Errorf("unexpected NewValidatorFromPath error: %+v", err)
		}
		if err := v.CheckAll(); err != nil {
			levelErrors, err := specerror.SplitLevel(err, rfc2119.Must)
			if err != nil {
				t.Errorf("unexpected non-multierror: %+v", err)
				return
			}
			for _, e := range levelErrors.Warnings {
				t.Logf("unexpected warning: %v", e)
			}
			if err := levelErrors.Error; err != nil {
				t.Errorf("unexpected MUST error(s): %+v", err)
			}
		}
	}
}

func TestRemoveMount(t *testing.T) {
	g, err := generate.New("linux")
	if err != nil {
		t.Fatal(err)
	}
	size := len(g.Mounts())
	g.RemoveMount("/dev/shm")
	if size-1 != len(g.Mounts()) {
		t.Errorf("Unable to remove /dev/shm from mounts")
	}
}

func TestEnvCaching(t *testing.T) {
	// Start with empty ENV and add a few
	g, err := generate.New("windows")
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"k1=v1", "k2=v2"}
	g.AddProcessEnv("k1", "v1")
	g.AddProcessEnv("k2", "v2")
	assert.Equal(t, expected, g.Config.Process.Env)

	// Test override and existing ENV
	g, err = generate.New("linux")
	if err != nil {
		t.Fatal(err)
	}
	expected = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm", "k1=v1", "k2=v4", "k3=v3"}
	g.AddProcessEnv("k1", "v1")
	g.AddProcessEnv("k2", "v2")
	g.AddProcessEnv("k3", "v3")
	g.AddProcessEnv("k2", "v4")
	assert.Equal(t, expected, g.Config.Process.Env)

	// Test empty ENV
	g, err = generate.New("windows")
	if err != nil {
		t.Fatal(err)
	}
	g.AddProcessEnv("", "")
	assert.Equal(t, []string(nil), g.Config.Process.Env)
}

func TestMultipleEnvCaching(t *testing.T) {
	// Start with empty ENV and add a few
	g, err := generate.New("windows")
	if err != nil {
		t.Fatal(err)
	}
	newEnvs := []string{"k1=v1", "k2=v2"}
	expected := []string{"k1=v1", "k2=v2"}
	g.AddMultipleProcessEnv(newEnvs)
	assert.Equal(t, expected, g.Config.Process.Env)

	// Test override and existing ENV
	g, err = generate.New("linux")
	if err != nil {
		t.Fatal(err)
	}
	newEnvs = []string{"k1=v1", "k2=v2", "k3=v3", "k2=v4"}
	expected = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm", "k1=v1", "k2=v4", "k3=v3"}
	g.AddMultipleProcessEnv(newEnvs)
	assert.Equal(t, expected, g.Config.Process.Env)

	// Test empty ENV
	g, err = generate.New("windows")
	if err != nil {
		t.Fatal(err)
	}
	g.AddMultipleProcessEnv([]string{})
	assert.Equal(t, []string(nil), g.Config.Process.Env)
}

func TestCloneIsolated(t *testing.T) {
	g, err := generate.New("linux")
	if err != nil {
		t.Fatal(err)
	}

	clone, err := g.Clone()
	if err != nil {
		t.Fatal(err)
	}

	// Mutating the clone must not affect the original.
	clone.SetHostname("clone-host")
	clone.AddProcessEnv("FOO", "bar")
	clone.AddLinuxMaskedPaths("/proc/kcore")
	if err := clone.AddProcessCapability("CAP_SYS_ADMIN"); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "mrsdalloway", g.Config.Hostname)
	assert.NotContains(t, g.Config.Process.Env, "FOO=bar")
	assert.Empty(t, g.Config.Linux.MaskedPaths)
	assert.NotContains(t, g.Config.Process.Capabilities.Bounding, "CAP_SYS_ADMIN")

	// The clone carries over the original state.
	assert.Equal(t, "clone-host", clone.Config.Hostname)
	assert.Contains(t, clone.Config.Process.Env, "FOO=bar")
	assert.Contains(t, clone.Config.Process.Env, "TERM=xterm")
}

func TestSaveDeterministic(t *testing.T) {
	g, err := generate.New("linux")
	if err != nil {
		t.Fatal(err)
	}

	var first, second bytes.Buffer
	if err := g.Save(&first, generate.ExportOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := g.Save(&second, generate.ExportOptions{}); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, first.String(), second.String(), "repeated Save must produce identical output")
}

func TestSaveDoesNotMutateEmptyLinux(t *testing.T) {
	g, err := generate.NewFromTemplate(strings.NewReader(`{"ociVersion":"1.1.0","linux":{}}`))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := g.Save(&buf, generate.ExportOptions{}); err != nil {
		t.Fatal(err)
	}

	// An empty linux section is omitted from the output, but Save must
	// not mutate the generator to achieve that.
	assert.NotContains(t, buf.String(), `"linux"`)
	assert.NotNil(t, g.Config.Linux, "Save must not mutate the generator")

	var second bytes.Buffer
	if err := g.Save(&second, generate.ExportOptions{}); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, buf.String(), second.String())
}

func TestSaveSeccompExportWithoutProfile(t *testing.T) {
	g, err := generate.NewFromTemplate(strings.NewReader(`{"ociVersion":"1.1.0"}`))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	err = g.Save(&buf, generate.ExportOptions{Seccomp: true})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "linux.seccomp")
}

func TestSaveToFileAtomicOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	original := []byte("original content")
	if err := os.WriteFile(path, original, 0o644); err != nil {
		t.Fatal(err)
	}

	// A failing export (seccomp-only output from a configuration
	// without a seccomp profile) must leave the file untouched.
	g, err := generate.NewFromTemplate(strings.NewReader(`{"ociVersion":"1.1.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	err = g.SaveToFile(path, generate.ExportOptions{Seccomp: true})
	assert.Error(t, err)

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, original, content, "failed SaveToFile must preserve the original file")

	// No temporary files may be left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, entries, 1)
}

func TestSaveToFileAtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	g, err := generate.New("linux")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.SaveToFile(path, generate.ExportOptions{}); err != nil {
		t.Fatal(err)
	}

	// The written file must be loadable by the same-version tooling.
	reloaded, err := generate.NewFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assert.NoError(t, reloaded.Check("linux"))

	// Regenerating over an existing file is deterministic.
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := generate.New("linux")
	if err != nil {
		t.Fatal(err)
	}
	if err := g2.SaveToFile(path, generate.ExportOptions{}); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, first, second)
}

func TestCheckPlatform(t *testing.T) {
	linuxGen, err := generate.New("linux")
	if err != nil {
		t.Fatal(err)
	}
	assert.NoError(t, linuxGen.CheckPlatform("linux"))

	windowsGen, err := generate.New("windows")
	if err != nil {
		t.Fatal(err)
	}
	assert.NoError(t, windowsGen.CheckPlatform("windows"))

	// A windows section conflicts with a linux target.
	err = windowsGen.CheckPlatform("linux")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "windows")

	// An empty platform-specific section is not a conflict.
	emptyLinux, err := generate.NewFromTemplate(strings.NewReader(`{"ociVersion":"1.1.0","linux":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	assert.NoError(t, emptyLinux.CheckPlatform("windows"))

	// Unsupported platforms are rejected.
	assert.Error(t, linuxGen.CheckPlatform("plan9"))
}

func TestPlatformInference(t *testing.T) {
	linuxGen, err := generate.New("linux")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "linux", linuxGen.Platform())

	windowsGen, err := generate.New("windows")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "windows", windowsGen.Platform())

	bare, err := generate.NewFromTemplate(strings.NewReader(`{"ociVersion":"1.1.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "", bare.Platform())
}

func TestCheck(t *testing.T) {
	// The default configurations must pass the same-version validator.
	for _, platform := range []string{"linux", "windows", "solaris"} {
		g, err := generate.New(platform)
		if err != nil {
			t.Fatal(err)
		}
		assert.NoError(t, g.Check(platform), "default %s configuration must validate", platform)
	}

	// An illegal capability is reported.
	g, err := generate.New("linux")
	if err != nil {
		t.Fatal(err)
	}
	g.Config.Process.Capabilities.Bounding = append(g.Config.Process.Capabilities.Bounding, "CAP_NOT_A_REAL_CAP")
	assert.Error(t, g.Check("linux"))

	// A platform conflict is reported and names the conflicting field.
	winGen, err := generate.New("windows")
	if err != nil {
		t.Fatal(err)
	}
	err = winGen.Check("linux")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "windows")
}
