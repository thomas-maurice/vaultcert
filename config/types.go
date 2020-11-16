package config

// SSHBackend struct to store ssh backend config
type SSHBackend struct {
	Path string `yaml:"path"`
}

// PKIBackend struct to store pki backend config
type PKIBackend struct {
	Path string `yaml:"path"`
}

// NSSDatabase struct to store nss dbs config
// i.e. firefox or chrome's cert stores
type NSSDatabase struct {
	Path string `yaml:"path"`
}

// Config global config struct
type Config struct {
	LoginCommand      string                 `yaml:"login_command"`
	DefaultSSHBackend string                 `yaml:"default_ssh_backend"`
	DefaultPKIBackend string                 `yaml:"default_pki_backend"`
	SSH               map[string]SSHBackend  `yaml:"ssh"`
	PKI               map[string]PKIBackend  `yaml:"pki"`
	NSS               map[string]NSSDatabase `yaml:"nss"`
}

// GetPKIBackendNames returns the names of all the pki backends
func (c *Config) GetPKIBackendNames() []string {
	var names []string
	for k := range c.PKI {
		names = append(names, k)
	}

	return names
}

// GetDefaultPKIBackendName gets the default pki backend name
func (c *Config) GetDefaultPKIBackendName() string {
	if c.DefaultPKIBackend != "" {
		return c.DefaultPKIBackend
	}

	var names []string
	for k := range c.PKI {
		names = append(names, k)
	}
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// GetSSHBackendNames returns the names of all the ssh backends
func (c *Config) GetSSHBackendNames() []string {
	var names []string
	for k := range c.SSH {
		names = append(names, k)
	}

	return names
}

// GetDefaultSSHBackendName returns the name of the default ssh backend
func (c *Config) GetDefaultSSHBackendName() string {
	if c.DefaultSSHBackend != "" {
		return c.DefaultSSHBackend
	}

	var names []string
	for k := range c.SSH {
		names = append(names, k)
	}
	if len(names) == 0 {
		return ""
	}
	return names[0]
}
