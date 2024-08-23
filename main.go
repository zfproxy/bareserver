package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/zfproxy/bareserver/bare"
	v1 "github.com/zfproxy/bareserver/v1"
	v2 "github.com/zfproxy/bareserver/v2"
	v3 "github.com/zfproxy/bareserver/v3"
)

func main() {
	var apiPath = "/ov/"
	var httpAddr = ":80"
	var httpsAddr = ":443"
	var staticDir = "/root/work/zfproxy/zfproxy/static"
	var errors = true
	var localAddress = ""
	var family = 0
	var maintainerFile = ""
	var certFile = "/etc/nginx/cert/cert.pem"
	var keyFile = "/etc/nginx/cert/key.pem"

	var rootCmd = &cobra.Command{
		Use:     "bare-server",
		Short:   "Bare server implementation in Go",
		Version: "0.1.0",
		Run: func(cmd *cobra.Command, args []string) {
			options := &bare.Options{
				LogErrors:      errors,
				LocalAddress:   localAddress,
				Family:         family,
				MaintainerFile: maintainerFile,
				APIPath:        apiPath,
				AddrHttp:       httpAddr,
				AddrHttps:      httpsAddr,
				StaticDir:      staticDir,
				CertFile:       certFile,
				KeyFile:        keyFile,
			}

			bareServer := bare.NewBareServer(options)

			v1.Register(bareServer)
			v2.Register(bareServer)
			v3.Register(bareServer)

			if err := bareServer.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "Error starting server: %s\n", err)
				os.Exit(1)
			}
		},
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
