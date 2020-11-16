package output

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Result struct {
	Error   bool        `json:"error" yaml:"error"`
	Message string      `json:"message" yaml:"message"`
	Data    interface{} `json:"data" yaml:"data"`
}

func Write(outputFormat string, isError bool, message string, data interface{}) {
	out := &Result{
		Error:   isError,
		Message: fmt.Sprintf(message),
		Data:    data,
	}
	fmt.Println(Serialize(outputFormat, out))
	if isError {
		os.Exit(1)
	}
}

func Serialize(format string, result *Result) string {
	switch format {
	case "json":
		return SerializeJSON(result)
	case "yaml":
		return SerializeYAML(result)
	default:
		return fmt.Sprintf("%v", result)
	}
}

func SerializeJSON(result *Result) string {
	b, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}

	return string(b)
}

func SerializeYAML(result *Result) string {
	b, err := yaml.Marshal(result)
	if err != nil {
		panic(err)
	}

	return string(b)
}
