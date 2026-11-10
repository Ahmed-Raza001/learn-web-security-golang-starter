package orders

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bootdotdev/learn-web-security/internal/storage"
)

type ShippingDetails struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	City       string `json:"city"`
	Region     string `json:"region"`
	PostalCode string `json:"postalCode"`
}

type serializedShippingDetails struct {
	Name       *string `json:"name"`
	Address    *string `json:"address"`
	City       *string `json:"city"`
	Region     *string `json:"region"`
	PostalCode *string `json:"postalCode"`
}

func EncryptShippingDetails(details ShippingDetails, keyring *storage.Keyring) (string, error) {
	if keyring == nil {
		return "", errors.New("shipping encryption requires a keyring")
	}

	plaintext, err := json.Marshal(details)
	if err != nil {
		return "", fmt.Errorf("serialize shipping details: %w", err)
	}

	encrypted, err := keyring.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt shipping details: %w", err)
	}

	return encrypted, nil
}

func DecryptShippingDetails(serialized string, keyring *storage.Keyring) (ShippingDetails, error) {
	if keyring == nil {
		return ShippingDetails{}, errors.New("shipping decryption requires a keyring")
	}

	plaintext, err := keyring.Decrypt(serialized)
	if err != nil {
		return ShippingDetails{}, fmt.Errorf("decrypt shipping details: %w", err)
	}

	var details serializedShippingDetails
	if err := json.Unmarshal(plaintext, &details); err != nil {
		return ShippingDetails{}, errors.New("invalid shipping details")
	}

	if details.Name == nil ||
		details.Address == nil ||
		details.City == nil ||
		details.Region == nil ||
		details.PostalCode == nil {
		return ShippingDetails{}, errors.New("invalid shipping details: missing fields")
	}

	return ShippingDetails{
		Name:       *details.Name,
		Address:    *details.Address,
		City:       *details.City,
		Region:     *details.Region,
		PostalCode: *details.PostalCode,
	}, nil
}
