package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"snoopy/snoopy"
)

func main() {
	app := &cli.App{
		Name:	"Snoopy-eBPF",
		Usage: 	"Catching Program Executions with eBPF",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name: 	"max-args",
				Value: 	16,
				Usage: 	"max # of execution arguments to record, 128 at most",
			},
			&cli.IntFlag{
				Name:	"max-envs",
				Value:	16,
				Usage: 	"max # of environment variables for the execution to record, 128 at most",
			},
			&cli.BoolFlag{
				Name:	"no-envs",
				Value: 	false,
				Usage:  "don't record environment variables (shortcut for --max-envs 0)",
			},
		},
		Action:	func(c *cli.Context) error {
			maxArg := c.Int("max-args")
			maxEnv := c.Int("max-envs")
			if c.Bool("no-envs") {
				maxEnv = 0
			}
			config := snoopy.Config{
				MaxArg: maxArg,
				MaxEnv: maxEnv,
			}
			s, err := snoopy.New(config)
			if err != nil {
				cli.ShowAppHelp(c)
				fmt.Println(err)
				return err
			}
			s.Run()
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
