package oidc

import (
	"fmt"

	"github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/terminal"
	"golang.org/x/oauth2"
)

// DeviceCodeUI presents a device authorization code to the user during the
// OAuth2 Device Authorization Grant flow.
type DeviceCodeUI func(deviceCode *oauth2.DeviceAuthResponse) error

// DeviceCodeUIConsoleQR renders deviceCode's verification URI as a QR code
// in the terminal.
func DeviceCodeUIConsoleQR(deviceCode *oauth2.DeviceAuthResponse) error {
	qrc, err := qrcode.New(deviceCode.VerificationURIComplete)
	if err != nil {
		return fmt.Errorf("could not generate QRCode: %w", err)
	}
	w := terminal.New()

	// save file
	if err = qrc.Save(w); err != nil {
		return fmt.Errorf("could not save image: %w", err)
	}

	return nil
}

// DeviceCodeUIConsoleText prints deviceCode's verification URI (and code, if
// the URI doesn't already embed it) to stdout.
func DeviceCodeUIConsoleText(deviceCode *oauth2.DeviceAuthResponse) error {
	if deviceCode.VerificationURIComplete == "" {
		fmt.Printf("Go to %v and enter code %v\n", deviceCode.VerificationURI, deviceCode.UserCode)
	} else {
		fmt.Printf("Go to %v\n", deviceCode.VerificationURIComplete)
	}

	return nil
}
