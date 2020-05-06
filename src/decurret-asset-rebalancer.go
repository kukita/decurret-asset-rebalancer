//
// Name
//   decurret-asset-rebalancer.go
//
// Description
//   This program is rebalancer of asset.
//
// Copyright (C) 2020 Keisuke Kukita
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/logutils"
)

// Config is struct
type Config struct {
	URLScheme          string  `json:"url_sheme"`
	URLHost            string  `json:"url_host"`
	APIAccessKey       string  `json:"api_access_key"`
	APISecuret         string  `json:"api_secret"`
	BtcTargetRatio     float64 `json:"btc_target_ratio"`
	EthTargetRatio     float64 `json:"eth_target_ratio"`
	BchTargetRatio     float64 `json:"bch_target_ratio"`
	LtcTargetRatio     float64 `json:"ltc_target_ratio"`
	XrpTargetRatio     float64 `json:"xrp_target_ratio"`
	RebalanceThreshold float64 `json:"rebalance_threshold"`
	LogLevel           string  `json:"log_level"`
}

// BalancesArray is struct
type BalancesArray struct {
	Balances []struct {
		CurrencyType          string `json:"currency_type"`
		YenCashAmount         string `json:"yen_cash_amount"`
		PaymentPossibleAmount string `json:"payment_possible_amount"`
		RestrictionAmount     string `json:"restriction_amount"`
		CurrencyCapacity      string `json:"currency_capacity"`
		LastCashAmount        string `json:"last_cash_amount"`
		Amount                string `json:"amount"`
	} `json:"balances"`
}

// Rate is struct
type Rate struct {
	Symbol          string `json:"symbol"`
	CurrentDatetime string `json:"current_datetime"`
	BidRate         string `json:"bid_rate"`
	AskRate         string `json:"ask_rate"`
	ChangeRatio     string `json:"change_ratio"`
	OpenPrice       string `json:"open_price"`
	HighPrice       string `json:"high_price"`
	LowPrice        string `json:"low_price"`
	PreClosePrice   string `json:"pre_close_price"`
}

// Order is struct
type Order struct {
	Symbol    string  `json:"symbol"`
	OrderQty  float64 `json:"order_qty"`
	OrderType string  `json:"order_type"`
	Side      string  `json:"side"`
}

// OrderResponce is struct
type OrderResponce struct {
	OrderID      string      `json:"order_id"`
	OrderQty     string      `json:"order_qty"`
	OrderType    string      `json:"order_type"`
	Price        string      `json:"price"`
	Side         string      `json:"side"`
	Symbol       string      `json:"symbol"`
	TriggerPrice interface{} `json:"trigger_price"`
}

func main() {
	// Checking if there is a configuration file (JSON file) and create a new one if it does not exist.
	configFilePath := os.Args[0][:len(os.Args[0])-len(filepath.Ext(os.Args[0]))] + ".json"
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		config := Config{
			"https",
			"api-trade.decurret.com",
			"<APIキー>",
			"<API Secret>",
			0.33,
			0.33,
			0.07,
			0.07,
			0.07,
			0.03,
			"INFO",
		}
		configJSON, err := json.Marshal(&config)
		if err != nil {
			log.Fatal(err)
		}

		configFile, err := os.Create(configFilePath)
		if err != nil {
			log.Fatal(err)
		}
		defer configFile.Close()

		configFile.WriteString(string(configJSON))
		log.Print("[INFO] ------------------------------------------------------------")
		log.Print("[INFO] Creating '" + configFilePath + "' has finished successfully. At First, please edit this file.")
		log.Print("[INFO] ------------------------------------------------------------")
		return
	}

	// Loading the configuration file (JSON file).
	configFile, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		log.Fatal(err)
	}
	var config Config
	json.Unmarshal(configFile, &config)

	// Setting "hashicorp/logutils".
	logFilePath := os.Args[0][:len(os.Args[0])-len(filepath.Ext(os.Args[0]))] + ".log"
	logfile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer logfile.Close()

	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"},
		MinLevel: logutils.LogLevel(config.LogLevel),
		Writer:   io.MultiWriter(logfile, os.Stdout),
	}
	log.SetOutput(filter)

	url := &url.URL{}
	url.Scheme = config.URLScheme
	url.Host = config.URLHost

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] JPYの残高を取得します")
	log.Print("[INFO] ------------------------------------------------------------")
	_, jpyYenAmount, _, nil := getRateAndBalance("JPY", url, &config)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("[INFO] JPYの残高: " + strconv.FormatFloat(jpyYenAmount, 'f', -1, 64))

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] BTCのレートと残高を取得します")
	log.Print("[INFO] ------------------------------------------------------------")
	btcRate, btcQuantity, btcYenAmount, nil := getRateAndBalance("BTC", url, &config)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("[INFO] BTCのレート: " + strconv.FormatFloat(btcRate, 'f', -1, 64))
	log.Print("[INFO] BTCの残高: " + strconv.FormatFloat(btcQuantity, 'f', -1, 64))
	log.Print("[INFO] BTCの日本円換算残高: " + strconv.FormatFloat(btcYenAmount, 'f', -1, 64))

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] ETHのレートと残高を取得します")
	log.Print("[INFO] ------------------------------------------------------------")
	ethRate, ethQuantity, ethYenAmount, nil := getRateAndBalance("ETH", url, &config)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("[INFO] ETHのレート: " + strconv.FormatFloat(ethRate, 'f', -1, 64))
	log.Print("[INFO] ETHの残高: " + strconv.FormatFloat(ethQuantity, 'f', -1, 64))
	log.Print("[INFO] ETHの日本円換算残高: " + strconv.FormatFloat(ethYenAmount, 'f', -1, 64))

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] BCHのレートと残高を取得します")
	log.Print("[INFO] ------------------------------------------------------------")
	bchRate, bchQuantity, bchYenAmount, nil := getRateAndBalance("BCH", url, &config)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("[INFO] BCHのレート: " + strconv.FormatFloat(bchRate, 'f', -1, 64))
	log.Print("[INFO] BCHの残高: " + strconv.FormatFloat(bchQuantity, 'f', -1, 64))
	log.Print("[INFO] BCHの日本円換算残高: " + strconv.FormatFloat(bchYenAmount, 'f', -1, 64))

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] LTCのレートと残高を取得します")
	log.Print("[INFO] ------------------------------------------------------------")
	ltcRate, ltcQuantity, ltcYenAmount, nil := getRateAndBalance("LTC", url, &config)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("[INFO] LTCのレート: " + strconv.FormatFloat(ltcRate, 'f', -1, 64))
	log.Print("[INFO] LTCの残高: " + strconv.FormatFloat(ltcQuantity, 'f', -1, 64))
	log.Print("[INFO] LTCの日本円換算残高: " + strconv.FormatFloat(ltcYenAmount, 'f', -1, 64))

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] XRPのレートと残高を取得します")
	log.Print("[INFO] ------------------------------------------------------------")
	xrpRate, xrpQuantity, xrpYenAmount, nil := getRateAndBalance("XRP", url, &config)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("[INFO] XRPのレート: " + strconv.FormatFloat(xrpRate, 'f', -1, 64))
	log.Print("[INFO] XRPの残高: " + strconv.FormatFloat(xrpQuantity, 'f', -1, 64))
	log.Print("[INFO] XRPの日本円換算残高: " + strconv.FormatFloat(xrpYenAmount, 'f', -1, 64))

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] 日本円換算残高の合計を算出します")
	log.Print("[INFO] ------------------------------------------------------------")
	totalYenAmount := jpyYenAmount + btcYenAmount + ethYenAmount + bchYenAmount + ltcYenAmount + ltcYenAmount
	log.Print("[INFO] 日本円換算残高合計: " + strconv.FormatFloat(totalYenAmount, 'f', -1, 64))

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] BTCのスイッチングを行います")
	log.Print("[INFO] ------------------------------------------------------------")
	if btcYenAmount < totalYenAmount*(config.BtcTargetRatio-config.RebalanceThreshold) {
		btcBuyYenAmount := totalYenAmount*config.BtcTargetRatio - btcYenAmount
		btcBuyQuantity := math.Trunc((btcBuyYenAmount/btcRate)*10000) / 10000
		log.Print("[INFO] BTCを " + strconv.FormatFloat(btcBuyYenAmount, 'f', -1, 64) + "円分 " + strconv.FormatFloat(btcBuyQuantity, 'f', -1, 64) + " 購入します")
		postOrder("BUY", "BTC", btcBuyQuantity, url, &config)
		btcBuyQuantity = 0
	} else if btcYenAmount > totalYenAmount*(config.BtcTargetRatio+config.RebalanceThreshold) {
		btcSellYenAmount := btcYenAmount - totalYenAmount*config.BtcTargetRatio
		btcSellQuantity := math.Trunc((btcSellYenAmount/btcRate)*10000) / 10000
		log.Print("[INFO] BTCを " + strconv.FormatFloat(btcSellYenAmount, 'f', -1, 64) + "円分 " + strconv.FormatFloat(btcSellQuantity, 'f', -1, 64) + " 売却します")
		postOrder("SELL", "BTC", btcSellQuantity, url, &config)
		btcSellQuantity = 0
	}

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] ETHのスイッチングを行います")
	log.Print("[INFO] ------------------------------------------------------------")
	if ethYenAmount < totalYenAmount*(config.EthTargetRatio-config.RebalanceThreshold) {
		ethBuyYenAmount := totalYenAmount*config.EthTargetRatio - ethYenAmount
		ethBuyQuantity := math.Trunc((ethBuyYenAmount/ethRate)*10000) / 10000
		log.Print("[INFO] ETHを " + strconv.FormatFloat(ethBuyYenAmount, 'f', -1, 64) + "円分 " + strconv.FormatFloat(ethBuyQuantity, 'f', -1, 64) + " 購入します")
		postOrder("BUY", "ETH", ethBuyQuantity, url, &config)
		ethBuyQuantity = 0
	} else if ethYenAmount > totalYenAmount*(config.EthTargetRatio+config.RebalanceThreshold) {
		ethSellYenAmount := ethYenAmount - totalYenAmount*config.EthTargetRatio
		ethSellQuantity := math.Trunc((ethSellYenAmount/ethRate)*10000) / 10000
		log.Print("[INFO] ETHを " + strconv.FormatFloat(ethSellYenAmount, 'f', -1, 64) + "円分 " + strconv.FormatFloat(ethSellQuantity, 'f', -1, 64) + " 売却します")
		postOrder("SELL", "ETH", ethSellQuantity, url, &config)
		ethSellQuantity = 0
	}

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] BCHのスイッチングを行います")
	log.Print("[INFO] ------------------------------------------------------------")
	if bchYenAmount < totalYenAmount*(config.BchTargetRatio-config.RebalanceThreshold) {
		bchBuyYenAmount := totalYenAmount*config.BchTargetRatio - bchYenAmount
		bchBuyQuantity := math.Trunc((bchBuyYenAmount/bchRate)*10000) / 10000
		log.Print("[INFO] BCHを " + strconv.FormatFloat(bchBuyYenAmount, 'f', -1, 64) + "円分 " + strconv.FormatFloat(bchBuyQuantity, 'f', -1, 64) + " 購入します")
		postOrder("BUY", "BCH", bchBuyQuantity, url, &config)
		bchBuyQuantity = 0
	} else if bchYenAmount > totalYenAmount*(config.BchTargetRatio+config.RebalanceThreshold) {
		bchSellYenAmount := bchYenAmount - totalYenAmount*config.BchTargetRatio
		bchSellQuantity := math.Trunc((bchSellYenAmount/bchRate)*10000) / 10000
		log.Print("[INFO] BCHを " + strconv.FormatFloat(bchSellYenAmount, 'f', -1, 64) + "円分 " + strconv.FormatFloat(bchSellQuantity, 'f', -1, 64) + " 売却します")
		postOrder("SELL", "BCH", bchSellQuantity, url, &config)
		bchSellQuantity = 0
	}

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] LTCのスイッチングを行います")
	log.Print("[INFO] ------------------------------------------------------------")
	if ltcYenAmount < totalYenAmount*(config.LtcTargetRatio-config.RebalanceThreshold) {
		ltcBuyYenAmount := totalYenAmount*config.LtcTargetRatio - ltcYenAmount
		ltcBuyQuantity := math.Trunc((ltcBuyYenAmount/ltcRate)*1000) / 1000
		log.Print("[INFO] LTCを " + strconv.FormatFloat(ltcBuyYenAmount, 'f', -1, 64) + "円分 " + strconv.FormatFloat(ltcBuyQuantity, 'f', -1, 64) + " 購入します")
		postOrder("BUY", "LTC", ltcBuyQuantity, url, &config)
		ltcBuyQuantity = 0
	} else if ltcYenAmount > totalYenAmount*(config.LtcTargetRatio+config.RebalanceThreshold) {
		ltcSellYenAmount := ltcYenAmount - totalYenAmount*config.LtcTargetRatio
		ltcSellQuantity := math.Trunc((ltcSellYenAmount/ltcRate)*1000) / 1000
		log.Print("[INFO] LTCを " + strconv.FormatFloat(ltcSellYenAmount, 'f', -1, 64) + "円分 " + strconv.FormatFloat(ltcSellQuantity, 'f', -1, 64) + " 売却します")
		postOrder("SELL", "LTC", ltcSellQuantity, url, &config)
		ltcSellQuantity = 0
	}

	log.Print("[INFO] ------------------------------------------------------------")
	log.Print("[INFO] XRPのスイッチングを行います")
	log.Print("[INFO] ------------------------------------------------------------")
	if xrpYenAmount < totalYenAmount*(config.XrpTargetRatio-config.RebalanceThreshold) {
		xrpBuyYenAmount := totalYenAmount*config.XrpTargetRatio - xrpYenAmount
		xrpBuyQuantity := math.Trunc(xrpBuyYenAmount / xrpRate)
		log.Print("[INFO] XRPを " + strconv.FormatFloat(xrpBuyYenAmount, 'f', -1, 64) + "円分 " + strconv.FormatFloat(xrpBuyQuantity, 'f', -1, 64) + " 購入します")
		postOrder("BUY", "XRP", xrpBuyQuantity, url, &config)
		xrpBuyQuantity = 0
	} else if xrpYenAmount > totalYenAmount*(config.XrpTargetRatio+config.RebalanceThreshold) {
		xrpSellYenAmount := xrpYenAmount - totalYenAmount*config.XrpTargetRatio
		xrpSellQuantity := math.Trunc(xrpSellYenAmount / xrpRate)
		log.Print("[INFO] XRPを " + strconv.FormatFloat(xrpSellYenAmount, 'f', -1, 64) + "円分 " + strconv.FormatFloat(xrpSellQuantity, 'f', -1, 64) + " 売却します")
		postOrder("SELL", "XRP", xrpSellQuantity, url, &config)
		xrpSellQuantity = 0
	}
}

func getRateAndBalance(tickerSymbol string, url *url.URL, config *Config) (float64, float64, float64, error) {
	// Set and encode URL
	url.Path = "/v1/api_deal/prices/symbols/" + tickerSymbol + "_JPY"
	q := url.Query()
	url.RawQuery = q.Encode()

	// Do API request
	rateJSON, err := doDeCurretAPI("GET", url, nil, config)
	if err != nil {
		return 0, 0, 0, err
	}

	// Parse API responce
	var rate Rate
	json.Unmarshal(rateJSON, &rate)
	bidRate, _ := strconv.ParseFloat(rate.BidRate, 64)
	askRate, _ := strconv.ParseFloat(rate.AskRate, 64)

	// Set and encode URL
	url.Path = "/v1/api_balance/balances/currencies/" + tickerSymbol
	q = url.Query()
	url.RawQuery = q.Encode()

	// Do API request
	balanceJSON, err := doDeCurretAPI("GET", url, nil, config)
	if err != nil {
		return (bidRate + askRate) / 2, 0, 0, err
	}

	// Parse API responce
	var balance BalancesArray
	json.Unmarshal(balanceJSON, &balance)
	balanceQuantity, err := strconv.ParseFloat(balance.Balances[0].Amount, 64)
	if err != nil {
		log.Fatal(err)
	}

	balanceAmount := (bidRate + askRate) / 2 * balanceQuantity
	return (bidRate + askRate) / 2, balanceQuantity, balanceAmount, nil
}

func postOrder(orderSide string, tickerSymbol string, quantity float64, url *url.URL, config *Config) {
	// Set and encode URL
	url.Path = "/v1/api_deal/orders"
	q := url.Query()
	url.RawQuery = q.Encode()

	// Create request body
	order := Order{
		tickerSymbol + "_JPY",
		quantity,
		"MARKET",
		orderSide,
	}

	reqBody, err := json.Marshal(&order)
	if err != nil {
		log.Fatal(err)
	}

	// Do API request
	resJSON, err := doDeCurretAPI("POST", url, reqBody, config)
	if err != nil {
		log.Fatal(err)
	}

	// Parse API responce
	var orderResponce OrderResponce
	json.Unmarshal(resJSON, &orderResponce)
}

func doDeCurretAPI(reqMethod string, url *url.URL, reqBody []byte, config *Config) ([]byte, error) {
	// Create http client
	client := &http.Client{}

	// Create REST request
	log.Print("[DEBUG] ------------------------------------------------------------")
	log.Print("[DEBUG] Creating API request is starting.")
	req, _ := http.NewRequest("", "", nil)
	switch reqMethod {
	case "GET":
		req, _ = http.NewRequest(reqMethod, url.String(), strings.NewReader(url.RawQuery))
	case "POST":
		req, _ = http.NewRequest(reqMethod, url.String(), bytes.NewBuffer(reqBody))
	}
	log.Print("[DEBUG] Creating API request has finished. Method: " + reqMethod + ", URL: " + url.String())

	// Create shared key
	log.Print("[DEBUG] ------------------------------------------------------------")
	log.Print("[DEBUG] Creating shared key is starting.")
	const charSet = "0123456789abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 32)
	for i := range b {
		b[i] = charSet[rand.Intn(len(charSet))]
	}
	sharedKey := string(b)
	log.Print("[DEBUG] Creating shared key has finished. Shared Key: " + sharedKey)

	// Create secret key
	log.Print("[DEBUG] ------------------------------------------------------------")
	log.Print("[DEBUG] Creating secret key is starting.")
	APISecuretHMAC := hmac.New(sha256.New, []byte(config.APISecuret)) //APIシークレットで
	APISecuretHMAC.Write([]byte(sharedKey))                           //共通鍵を署名し
	secretKey := hex.EncodeToString(APISecuretHMAC.Sum(nil))          //16進エンコーディングしシークレットキーを作成
	log.Print("[DEBUG] API Secret: " + config.APISecuret)
	log.Print("[DEBUG] Creating secret key has finished. Secret Key: " + secretKey)

	// Create message
	log.Print("[DEBUG] ------------------------------------------------------------")
	log.Print("[DEBUG] Creating message is starting.")
	builder := &strings.Builder{}
	builder.Grow(1024)
	builder.WriteString(sharedKey)
	builder.WriteString("&")
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)
	builder.WriteString(timestamp) //epoch/Unix timestamp
	builder.WriteString("&")
	builder.WriteString(reqMethod) //Request method
	builder.WriteString("\n")
	builder.WriteString(url.Path) //URL path
	builder.WriteString("\n")
	builder.WriteString(url.RawQuery) //URL raw query
	builder.WriteString("\n")
	builder.WriteString(url.Host) //URL host
	builder.WriteString("\n")
	sha256ReqBody := sha256.Sum256([]byte(reqBody))
	body := string(hex.EncodeToString(sha256ReqBody[:]))
	builder.WriteString(body) //Request body
	message := builder.String()
	log.Print("[DEBUG] Creating message has finished.\n" + message)

	// Create signature
	log.Print("[DEBUG] ------------------------------------------------------------")
	log.Print("[DEBUG] Creating signature is staring")
	SecuretKeyHMAC := hmac.New(sha256.New, []byte(secretKey)) //シークレットキーで
	SecuretKeyHMAC.Write([]byte(message))                     //メッセージを署名し
	signature := hex.EncodeToString(SecuretKeyHMAC.Sum(nil))  //16進エンコーディングしシグネチャーを作成
	log.Print("[DEBUG] Creating signature has finished. Signature: " + signature)

	// Add header
	log.Print("[DEBUG] ------------------------------------------------------------")
	log.Print("[DEBUG] Adding HTTP header is staring")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Access-Apikey", config.APIAccessKey)
	req.Header.Add("X-Access-Signature", signature)
	req.Header.Add("X-Access-Signaturetime", timestamp)
	req.Header.Add("X-Access-Swapinfo", "sha256/"+sharedKey)
	log.Print("[DEBUG] Adding HTTP header has finished.")
	reqDump, _ := httputil.DumpRequestOut(req, true)
	log.Print("[DEBUG] REST API Request: ↓ \n" + string(reqDump))
	// Do REST API request
	log.Print("[DEBUG] ------------------------------------------------------------")
	log.Print("[DEBUG] Doing REST API request is staring")
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	resDump, _ := httputil.DumpResponse(res, true)
	log.Print("[DEBUG] Doing REST API request has finished. StatusCode: " + strconv.Itoa(res.StatusCode))
	log.Print("[DEBUG] REST API Response: ↓ \n" + string(resDump))

	// Return responce body
	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return resBody, nil
}
