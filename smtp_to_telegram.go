package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	configHandler "github.com/KevinCFechtel/goConfigHandler"
	units "github.com/docker/go-units"
	"github.com/jhillyerd/enmime"
	"github.com/phires/go-guerrilla"
	"github.com/phires/go-guerrilla/backends"
	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
	"github.com/urfave/cli/v2"
)

var (
	Version string = "UNKNOWN_RELEASE"
	logger  log.Logger
)

const (
	BodyTruncated = "\n\n[truncated]"
)

type SmtpConfig struct {
	smtpListen          string
	smtpPrimaryHost     string
	smtpMaxEnvelopeSize int64
}

type TelegramConfig struct {
	telegramChatIds                  string
	telegramBotToken                 string
	telegramApiPrefix                string
	telegramApiTimeoutSeconds        float64
	messageTemplate                  string
	forwardedAttachmentMaxSize       int
	forwardedAttachmentMaxPhotoSize  int
	forwardedAttachmentRespectErrors bool
	messageLengthToSendAsFile        uint
}

type Configuration struct {
	SmtpListen          			 string `json:"SmtpListen"`
	SmtpPrimaryHost     			 string `json:"SmtpPrimaryHost"`
	SmtpMaxEnvelopeSize 			 string `json:"SmtpMaxEnvelopeSize"`
	TelegramChatIds                  string `json:"TelegramChatIds"`
	TelegramBotToken                 string `json:"TelegramBotToken"`
	TelegramApiPrefix                string `json:"TelegramApiPrefix"`
	TelegramApiTimeoutSeconds        float64 `json:"TelegramApiTimeoutSeconds"`
	MessageTemplate                  string `json:"MessageTemplate"`
	ForwardedAttachmentMaxSize       string `json:"ForwardedAttachmentMaxSize"`
	ForwardedAttachmentMaxPhotoSize  string `json:"ForwardedAttachmentMaxPhotoSize"`
	ForwardedAttachmentRespectErrors bool `json:"ForwardedAttachmentRespectErrors"`
	MessageLengthToSendAsFile        uint `json:"MessageLengthToSendAsFile"`
}

type TelegramAPIMessageResult struct {
	Ok     bool                `json:"ok"`
	Result *TelegramAPIMessage `json:"result"`
}

type TelegramAPIMessage struct {
	// https://core.telegram.org/bots/api#message
	MessageId json.Number `json:"message_id"`
}

type FormattedEmail struct {
	text        string
	attachments []*FormattedAttachment
}

const (
	ATTACHMENT_TYPE_DOCUMENT = iota
	ATTACHMENT_TYPE_PHOTO    = iota
)

type FormattedAttachment struct {
	filename string
	caption  string
	content  []byte
	fileType int
}

func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		panic(fmt.Sprintf("Unable to detect hostname: %s", err))
	}
	return hostname
}

func main() {
	app := cli.NewApp()
	app.Name = "smtp_to_telegram"
	app.Usage = "A small program which listens for SMTP and sends " +
		"all incoming Email messages to Telegram."
	app.Version = Version
	app.Action = func(c *cli.Context) error {
		configuration := Configuration{}
		err := configHandler.GetConfig("localFile", c.String("configFilePath"), &configuration, GetHostname())
		if err != nil {
			panic(fmt.Sprintf("Unable to read config: %s", err))
		}

		smtpConfig := initSmtpConfig(configuration)

		telegramConfig := initTelegramConfig(configuration)
		
		d, err := SmtpStart(smtpConfig, telegramConfig)
		if err != nil {
			panic(fmt.Sprintf("start error: %s", err))
		}

		sigHandler(d)
		return nil
	}
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "configFilePath",
			Value:   "conf.json",
			Usage:   "Filepath of the config file",
			EnvVars: []string{"ST_CONFIG_FILE_PATH"},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
}

func initSmtpConfig(configuration Configuration) (smtpConfig *SmtpConfig) {
	smtpMaxEnvelopeSize, err := units.FromHumanSize("50m")
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	smtpConfig = &SmtpConfig{
		smtpListen:          "127.0.0.1:25",
		smtpPrimaryHost:     GetHostname(),
		smtpMaxEnvelopeSize: smtpMaxEnvelopeSize,
	}

	if(configuration.SmtpListen != "") {
		smtpConfig.smtpListen = configuration.SmtpListen
	}

	if(configuration.SmtpPrimaryHost != "") {
		smtpConfig.smtpPrimaryHost = configuration.SmtpPrimaryHost
	}

	if(configuration.SmtpMaxEnvelopeSize != "") {
		smtpMaxEnvelopeSize, err := units.FromHumanSize(configuration.SmtpMaxEnvelopeSize)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}
		smtpConfig.smtpMaxEnvelopeSize = smtpMaxEnvelopeSize
	}

	return smtpConfig
}

func initTelegramConfig(configuration Configuration) (telegramConfig *TelegramConfig){
	forwardedAttachmentMaxSize, err := units.FromHumanSize("10m")
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	forwardedAttachmentMaxPhotoSize, err := units.FromHumanSize("10m")
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	telegramConfig = &TelegramConfig{
		telegramChatIds:                  "",
		telegramBotToken:                 "",
		telegramApiPrefix:                "https://api.telegram.org/",
		telegramApiTimeoutSeconds:        0,
		messageTemplate:                  "From: {from}\\nSubject: {subject}\\n\\n{body}\\n\\n{attachments_details}",
		forwardedAttachmentMaxSize:       int(forwardedAttachmentMaxSize),
		forwardedAttachmentMaxPhotoSize:  int(forwardedAttachmentMaxPhotoSize),
		forwardedAttachmentRespectErrors: false,
		messageLengthToSendAsFile:        4095,
	}

	if(configuration.TelegramChatIds != "") {
		telegramConfig.telegramChatIds = configuration.TelegramChatIds
	}

	if(configuration.TelegramBotToken != "") {
		telegramConfig.telegramBotToken = configuration.TelegramBotToken
	}

	if(configuration.TelegramApiPrefix != "") {
		telegramConfig.telegramApiPrefix = configuration.TelegramApiPrefix
	}

	if(configuration.TelegramApiTimeoutSeconds != 0) {
		telegramConfig.telegramApiTimeoutSeconds = configuration.TelegramApiTimeoutSeconds
	}

	if(configuration.MessageTemplate != "") {
		telegramConfig.messageTemplate = configuration.MessageTemplate
	}

	if(configuration.ForwardedAttachmentMaxSize != "") {
		forwardedAttachmentMaxSize, err := units.FromHumanSize(configuration.ForwardedAttachmentMaxSize)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}
		telegramConfig.forwardedAttachmentMaxSize = int(forwardedAttachmentMaxSize)
	}

	if(configuration.ForwardedAttachmentMaxPhotoSize != "") {
		forwardedAttachmentMaxPhotoSize, err := units.FromHumanSize(configuration.ForwardedAttachmentMaxPhotoSize)
		if err != nil {
			fmt.Printf("%s\n", err)
			os.Exit(1)
		}
		telegramConfig.forwardedAttachmentMaxPhotoSize = int(forwardedAttachmentMaxPhotoSize)
	}

	if(configuration.ForwardedAttachmentRespectErrors) {
		telegramConfig.forwardedAttachmentRespectErrors = configuration.ForwardedAttachmentRespectErrors
	}

	if(configuration.MessageLengthToSendAsFile != 0) {
		telegramConfig.messageLengthToSendAsFile = configuration.MessageLengthToSendAsFile
	}

	return telegramConfig;
}

func SmtpStart(
	smtpConfig *SmtpConfig, telegramConfig *TelegramConfig) (guerrilla.Daemon, error) {

	cfg := &guerrilla.AppConfig{LogFile: log.OutputStdout.String()}

	cfg.AllowedHosts = []string{"."}

	sc := guerrilla.ServerConfig{
		IsEnabled:       true,
		ListenInterface: smtpConfig.smtpListen,
		MaxSize:         smtpConfig.smtpMaxEnvelopeSize,
	}
	cfg.Servers = append(cfg.Servers, sc)

	bcfg := backends.BackendConfig{
		"save_workers_size":  3,
		"save_process":       "HeadersParser|Header|Hasher|TelegramBot",
		"log_received_mails": true,
		"primary_mail_host":  smtpConfig.smtpPrimaryHost,
	}
	cfg.BackendConfig = bcfg

	daemon := guerrilla.Daemon{Config: cfg}
	daemon.AddProcessor("TelegramBot", TelegramBotProcessorFactory(telegramConfig))

	logger = daemon.Log()

	err := daemon.Start()
	return daemon, err
}

func TelegramBotProcessorFactory(
	telegramConfig *TelegramConfig) func() backends.Decorator {
	return func() backends.Decorator {
		// https://github.com/flashmob/go-guerrilla/wiki/Backends,-configuring-and-extending

		return func(p backends.Processor) backends.Processor {
			return backends.ProcessWith(
				func(e *mail.Envelope, task backends.SelectTask) (backends.Result, error) {
					if task == backends.TaskSaveMail {
						err := SendEmailToTelegram(e, telegramConfig)
						if err != nil {
							return backends.NewResult(fmt.Sprintf("554 Error: %s", err)), err
						}
						return p.Process(e, task)
					}
					return p.Process(e, task)
				},
			)
		}
	}
}

func SendEmailToTelegram(e *mail.Envelope,
	telegramConfig *TelegramConfig) error {

	message, err := FormatEmail(e, telegramConfig)
	if err != nil {
		return err
	}

	client := http.Client{
		Timeout: time.Duration(telegramConfig.telegramApiTimeoutSeconds*1000) * time.Millisecond,
	}

	for _, chatId := range strings.Split(telegramConfig.telegramChatIds, ",") {
		sentMessage, err := SendMessageToChat(message, chatId, telegramConfig, &client)
		if err != nil {
			// If unable to send at least one message -- reject the whole email.
			return errors.New(SanitizeBotToken(err.Error(), telegramConfig.telegramBotToken))
		}

		for _, attachment := range message.attachments {
			err = SendAttachmentToChat(attachment, chatId, telegramConfig, &client, sentMessage)
			if err != nil {
				err = errors.New(SanitizeBotToken(err.Error(), telegramConfig.telegramBotToken))
				if telegramConfig.forwardedAttachmentRespectErrors {
					return err
				} else {
					logger.Errorf("Ignoring attachment sending error: %s", err)
				}
			}
		}
	}
	return nil
}

func SendMessageToChat(
	message *FormattedEmail,
	chatId string,
	telegramConfig *TelegramConfig,
	client *http.Client,
) (*TelegramAPIMessage, error) {
	// The native golang's http client supports
	// http, https and socks5 proxies via HTTP_PROXY/HTTPS_PROXY env vars
	// out of the box.
	//
	// See: https://golang.org/pkg/net/http/#ProxyFromEnvironment
	resp, err := client.PostForm(
		// https://core.telegram.org/bots/api#sendmessage
		fmt.Sprintf(
			"%sbot%s/sendMessage?disable_web_page_preview=true",
			telegramConfig.telegramApiPrefix,
			telegramConfig.telegramBotToken,
		),
		url.Values{"chat_id": {chatId}, "text": {message.text}},
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf(
			"Non-200 response from Telegram: (%d) %s",
			resp.StatusCode,
			EscapeMultiLine(body),
		)
	}

	j, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading json body of sendMessage: %v", err)
	}
	result := &TelegramAPIMessageResult{}
	err = json.Unmarshal(j, result)
	if err != nil {
		return nil, fmt.Errorf("error parsing json body of sendMessage: %v", err)
	}
	if !result.Ok {
		return nil, fmt.Errorf("ok != true: %s", j)
	}
	return result.Result, nil
}

func SendAttachmentToChat(
	attachment *FormattedAttachment,
	chatId string,
	telegramConfig *TelegramConfig,
	client *http.Client,
	sentMessage *TelegramAPIMessage,
) error {
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)
	var method string
	// https://core.telegram.org/bots/api#sending-files
	if attachment.fileType == ATTACHMENT_TYPE_DOCUMENT {
		// https://core.telegram.org/bots/api#senddocument
		method = "sendDocument"
		panicIfError(w.WriteField("chat_id", chatId))
		panicIfError(w.WriteField("reply_to_message_id", sentMessage.MessageId.String()))
		panicIfError(w.WriteField("caption", attachment.caption))
		// TODO maybe reuse files sent to multiple chats via file_id?
		dw, err := w.CreateFormFile("document", attachment.filename)
		panicIfError(err)
		_, err = dw.Write(attachment.content)
		panicIfError(err)
	} else if attachment.fileType == ATTACHMENT_TYPE_PHOTO {
		// https://core.telegram.org/bots/api#sendphoto
		method = "sendPhoto"
		panicIfError(w.WriteField("chat_id", chatId))
		panicIfError(w.WriteField("reply_to_message_id", sentMessage.MessageId.String()))
		panicIfError(w.WriteField("caption", attachment.caption))
		// TODO maybe reuse files sent to multiple chats via file_id?
		dw, err := w.CreateFormFile("photo", attachment.filename)
		panicIfError(err)
		_, err = dw.Write(attachment.content)
		panicIfError(err)
	} else {
		panic(fmt.Errorf("unknown file type %d", attachment.fileType))
	}
	w.Close()

	resp, err := client.Post(
		fmt.Sprintf(
			"%sbot%s/%s?disable_notification=true",
			telegramConfig.telegramApiPrefix,
			telegramConfig.telegramBotToken,
			method,
		),
		w.FormDataContentType(),
		buf,
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf(
			"Non-200 response from Telegram: (%d) %s",
			resp.StatusCode,
			EscapeMultiLine(body),
		)
	}
	return nil
}

func FormatEmail(e *mail.Envelope, telegramConfig *TelegramConfig) (*FormattedEmail, error) {
	reader := e.NewReader()
	env, err := enmime.ReadEnvelope(reader)
	if err != nil {
		return nil, fmt.Errorf("%s\n\nError occurred during email parsing: %v", e, err)
	}
	text := env.Text

	attachmentsDetails := []string{}
	attachments := []*FormattedAttachment{}

	doParts := func(emoji string, parts []*enmime.Part) {
		for _, part := range parts {
			if bytes.Equal(part.Content, []byte(env.Text)) {
				continue
			}
			if text == "" && part.ContentType == "text/plain" && part.FileName == "" {
				text = string(part.Content)
				continue
			}
			action := "discarded"
			contentType := GuessContentType(part.ContentType, part.FileName)
			if FileIsImage(contentType) && len(part.Content) <= telegramConfig.forwardedAttachmentMaxPhotoSize {
				action = "sending..."
				attachments = append(attachments, &FormattedAttachment{
					filename: part.FileName,
					caption:  part.FileName,
					content:  part.Content,
					fileType: ATTACHMENT_TYPE_PHOTO,
				})
			} else {
				if len(part.Content) <= telegramConfig.forwardedAttachmentMaxSize {
					action = "sending..."
					attachments = append(attachments, &FormattedAttachment{
						filename: part.FileName,
						caption:  part.FileName,
						content:  part.Content,
						fileType: ATTACHMENT_TYPE_DOCUMENT,
					})
				}
			}
			line := fmt.Sprintf(
				"- %s %s (%s) %s, %s",
				emoji,
				part.FileName,
				contentType,
				units.HumanSize(float64(len(part.Content))),
				action,
			)
			attachmentsDetails = append(attachmentsDetails, line)
		}
	}
	doParts("🔗", env.Inlines)
	doParts("📎", env.Attachments)
	for _, part := range env.OtherParts {
		line := fmt.Sprintf(
			"- ❔ %s (%s) %s, discarded",
			part.FileName,
			GuessContentType(part.ContentType, part.FileName),
			units.HumanSize(float64(len(part.Content))),
		)
		attachmentsDetails = append(attachmentsDetails, line)
	}
	for _, e := range env.Errors {
		logger.Errorf("Envelope error: %s", e.Error())
	}

	if text == "" {
		text = e.Data.String()
	}

	formattedAttachmentsDetails := ""
	if len(attachmentsDetails) > 0 {
		formattedAttachmentsDetails = fmt.Sprintf(
			"Attachments:\n%s",
			strings.Join(attachmentsDetails, "\n"),
		)
	}

	fullMessageText, truncatedMessageText := FormatMessage(
		e.MailFrom.String(),
		JoinEmailAddresses(e.RcptTo),
		env.GetHeader("subject"),
		text,
		formattedAttachmentsDetails,
		telegramConfig,
	)
	if truncatedMessageText == "" { // no need to truncate
		return &FormattedEmail{
			text:        fullMessageText,
			attachments: attachments,
		}, nil
	} else {
		if len(fullMessageText) > telegramConfig.forwardedAttachmentMaxSize {
			return nil, fmt.Errorf(
				"the message length (%d) is larger than `forwarded-attachment-max-size` (%d)",
				len(fullMessageText),
				telegramConfig.forwardedAttachmentMaxSize,
			)
		}
		at := &FormattedAttachment{
			filename: "full_message.txt",
			caption:  "Full message",
			content:  []byte(fullMessageText),
			fileType: ATTACHMENT_TYPE_DOCUMENT,
		}
		attachments := append([]*FormattedAttachment{at}, attachments...)
		return &FormattedEmail{
			text:        truncatedMessageText,
			attachments: attachments,
		}, nil
	}
}

func FormatMessage(
	from string, to string, subject string, text string,
	formattedAttachmentsDetails string,
	telegramConfig *TelegramConfig,
) (string, string) {
	fullMessageText := strings.TrimSpace(
		strings.NewReplacer(
			"\\n", "\n",
			"{from}", from,
			"{to}", to,
			"{subject}", subject,
			"{body}", strings.TrimSpace(text),
			"{attachments_details}", formattedAttachmentsDetails,
		).Replace(telegramConfig.messageTemplate),
	)
	fullMessageRunes := []rune(fullMessageText)
	if uint(len(fullMessageRunes)) <= telegramConfig.messageLengthToSendAsFile {
		// No need to truncate
		return fullMessageText, ""
	}

	emptyMessageText := strings.TrimSpace(
		strings.NewReplacer(
			"\\n", "\n",
			"{from}", from,
			"{to}", to,
			"{subject}", subject,
			"{body}", strings.TrimSpace(fmt.Sprintf(".%s", BodyTruncated)),
			"{attachments_details}", formattedAttachmentsDetails,
		).Replace(telegramConfig.messageTemplate),
	)
	emptyMessageRunes := []rune(emptyMessageText)
	if uint(len(emptyMessageRunes)) >= telegramConfig.messageLengthToSendAsFile {
		// Impossible to truncate properly
		return fullMessageText, string(fullMessageRunes[:telegramConfig.messageLengthToSendAsFile])
	}

	maxBodyLength := telegramConfig.messageLengthToSendAsFile - uint(len(emptyMessageRunes))
	truncatedMessageText := strings.TrimSpace(
		strings.NewReplacer(
			"\\n", "\n",
			"{from}", from,
			"{to}", to,
			"{subject}", subject,
			// TODO cut by paragraphs + respect formatting
			"{body}", strings.TrimSpace(fmt.Sprintf("%s%s",
				string([]rune(strings.TrimSpace(text))[:maxBodyLength]), BodyTruncated)),
			"{attachments_details}", formattedAttachmentsDetails,
		).Replace(telegramConfig.messageTemplate),
	)
	if uint(len([]rune(truncatedMessageText))) > telegramConfig.messageLengthToSendAsFile {
		panic(fmt.Errorf("expected length of truncated message:\n%d\n%s",
			maxBodyLength, truncatedMessageText))
	}
	return fullMessageText, truncatedMessageText
}

func GuessContentType(contentType string, filename string) string {
	if contentType != "application/octet-stream" {
		return contentType
	}
	guessedType := mime.TypeByExtension(filepath.Ext(filename))
	if guessedType != "" {
		return guessedType
	}
	return contentType // Give up
}

func FileIsImage(contentType string) bool {
	switch contentType {
	case
		// "image/gif",  // sent as a static image
		// "image/x-ms-bmp",  // rendered as document
		"image/jpeg",
		"image/png":
		return true
	}
	return false
}

func JoinEmailAddresses(a []mail.Address) string {
	s := []string{}
	for _, aa := range a {
		s = append(s, aa.String())
	}
	return strings.Join(s, ", ")
}

func EscapeMultiLine(b []byte) string {
	// Apparently errors returned by smtp must not contain newlines,
	// otherwise the data after the first newline is not getting
	// to the parsed message.
	s := string(b)
	s = strings.Replace(s, "\r", "\\r", -1)
	s = strings.Replace(s, "\n", "\\n", -1)
	return s
}

func SanitizeBotToken(s string, botToken string) string {
	return strings.Replace(s, botToken, "***", -1)
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

func sigHandler(d guerrilla.Daemon) {
	signalChannel := make(chan os.Signal, 1)

	signal.Notify(signalChannel,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGINT,
	)
	for range signalChannel {
		logger.Info("Shutdown signal caught")
		go func() {
			select {
			// exit if graceful shutdown not finished in 60 sec.
			case <-time.After(time.Second * 60):
				logger.Error("graceful shutdown timed out")
				os.Exit(1)
			default:
			}
		}()
		d.Shutdown()
		logger.Info("Shutdown completed, exiting.")
		return
	}
}
