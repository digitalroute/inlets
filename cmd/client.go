package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/digitalroute/inlets/pkg/client"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	inletsCmd.AddCommand(clientCmd)
	clientCmd.Flags().StringP("remote", "r", "127.0.0.1:8000", "server address i.e. 127.0.0.1:8000")
	clientCmd.Flags().StringP("upstream", "u", "", "upstream server i.e. http://127.0.0.1:3000")
	clientCmd.Flags().StringP("token", "t", "", "authentication token")
	clientCmd.Flags().StringP("token-from", "f", "", "read the authentication token from a file")
	clientCmd.Flags().StringP("token-source", "s", "", "input | file | cognito")
	clientCmd.Flags().Bool("print-token", true, "prints the token in server mode")
}

type UpstreamParser interface {
	Parse(input string) map[string]string
}

type ArgsUpstreamParser struct {
}

func (a *ArgsUpstreamParser) Parse(input string) map[string]string {
	upstreamMap := buildUpstreamMap(input)

	return upstreamMap
}

func buildUpstreamMap(args string) map[string]string {
	items := make(map[string]string)

	entries := strings.Split(args, ",")
	for _, entry := range entries {
		kvp := strings.Split(entry, "=")
		if len(kvp) == 1 {
			items[""] = strings.TrimSpace(kvp[0])
		} else {
			items[strings.TrimSpace(kvp[0])] = strings.TrimSpace(kvp[1])
		}
	}
	return items
}

// clientCmd represents the client sub command.
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start the tunnel client.",
	Long: `Start the tunnel client.

Example: inlets client --remote=192.168.0.101:80 --upstream=http://127.0.0.1:3000 
Note: You can pass the --token argument followed by a token value to both the server and client to prevent unauthorized connections to the tunnel.`,
	RunE: runClient,
}

// runClient does the actual work of reading the arguments passed to the client sub command.
func runClient(cmd *cobra.Command, _ []string) error {
	upstream, err := cmd.Flags().GetString("upstream")
	if err != nil {
		return errors.Wrap(err, "failed to get 'upstream' value")
	}

	if len(upstream) == 0 {
		return errors.New("upstream is missing in the client argument")
	}

	argsUpstreamParser := ArgsUpstreamParser{}
	upstreamMap := argsUpstreamParser.Parse(upstream)
	for k, v := range upstreamMap {
		log.Printf("Upstream: %s => %s\n", k, v)
	}

	remote, err := cmd.Flags().GetString("remote")
	if err != nil {
		return errors.Wrap(err, "failed to get 'remote' value.")
	}

	token, err := handleAuthConf(cmd)
	if err != nil {
		return errors.Wrap(err, "failed to get token.")
	}

	printToken, err := cmd.Flags().GetBool("print-token")
	if err != nil {
		return errors.Wrap(err, "failed to get 'print-token' value.")
	}

	if len(token) > 0 && printToken {
		log.Printf("Token: %q", token)
	}

	inletsClient := client.Client{
		Remote:      remote,
		UpstreamMap: upstreamMap,
		Token:       token,
	}

	if err := inletsClient.Connect(); err != nil {
		return err
	}

	return nil
}

func handleAuthConf(cmd *cobra.Command) (string, error) {
	var token string
	auth, err := cmd.Flags().GetString("token-source")

	if err != nil {
		//use local stored token...
		tokenFile, _ := cmd.Flags().GetString("token-from")
		tokenVal, _ := cmd.Flags().GetString("token")
		if len(tokenFile) > 0 {
			fileData, errReadFile := ioutil.ReadFile(tokenFile)
			if errReadFile != nil {
				return "", errors.Wrap(err, fmt.Sprintf("unable to load file: %s", tokenFile))
			}
			token = string(fileData)
		} else if len(tokenVal) > 0 {
			token = tokenVal
		}
	}

	if strings.EqualFold("cognito", auth) {
		cognitoUser := os.Getenv("COGNITO_USER")
		cognitoPass := os.Getenv("COGNITO_PASS")
		cognitoClientId := os.Getenv("COGNITO_CLIENTID")
		awsRegion := os.Getenv("AWS_DEFAULT_REGION")

		//cognitoClientId := os.Getenv("COGNITO_CLIENTID")
		//fmt.Println("Using Token: '" + cognitoUser + "' : '" + cognitoPass + "' : '" + cognitoClientId + "'")
		client := cognitoidentityprovider.New(session.New(), &aws.Config{Region: aws.String(awsRegion)})

		params := &cognitoidentityprovider.InitiateAuthInput{
			AuthFlow: aws.String("USER_PASSWORD_AUTH"),
			AuthParameters: map[string]*string{
				"USERNAME": aws.String(cognitoUser),
				"PASSWORD": aws.String(cognitoPass),
			},
			ClientId: aws.String(cognitoClientId),
		}

		authResp, err := client.InitiateAuth(params)
		if err != nil {
			return "", err
		}
		token = *authResp.AuthenticationResult.AccessToken
	}
	return token, nil
}
