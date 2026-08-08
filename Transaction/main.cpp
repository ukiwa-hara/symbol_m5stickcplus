#include <Arduino.h>
#include <M5StickCPlus.h>

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>

#include <ArduinoJson.h>
#include <Ed25519.h>
#include <SHA3.h>

#include <Preferences.h>

Preferences preferences;

// ============================================================
// Symbol REST node
// ============================================================

const char* NODE_URL =
    "https://sym-test-03.opening-line.jp:3001";

// ============================================================
// Account B
// ============================================================
//
// Symbol address:
//
// T... の39文字アドレスを指定する。
// ハイフン付きでもOK。
// ============================================================

const char* ACCOUNT_B_ADDRESS =
    "TAQSGS6Q7SUUFIQZG5TLVR3K3YUU35UK6G3WXBQ";

// ============================================================
// Symbol constants
// ============================================================

static const uint8_t TESTNET_NETWORK = 0x98;
static const uint16_t TRANSFER_TYPE = 0x4154;

static const uint64_t TRANSFER_AMOUNT =
    1000000ULL;       // 1 XYM

static const uint64_t FEE_MULTIPLIER =
    100;              // max fee = size * 100

static const uint32_t DEADLINE_SECONDS =
    2 * 60 * 60;      // 2 hours


// ============================================================
// Runtime network information
// ============================================================

uint8_t generationHashSeed[32];

uint64_t epochAdjustment = 0;

uint64_t currencyMosaicId = 0;

uint8_t networkIdentifier = 0;


// ============================================================
// Utility
// ============================================================

int hexValue(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    return -1;
}


bool hexToBytes(
    const char* input,
    uint8_t* output,
    size_t outputSize)
{
    size_t len = strlen(input);

    if (len != outputSize * 2)
        return false;

    for (size_t i = 0; i < outputSize; i++)
    {
        int hi = hexValue(input[i * 2]);
        int lo = hexValue(input[i * 2 + 1]);

        if (hi < 0 || lo < 0)
            return false;

        output[i] =
            (uint8_t)((hi << 4) | lo);
    }

    return true;
}


void secureZero(void* data, size_t length)
{
    volatile uint8_t* bytes = static_cast<volatile uint8_t*>(data);

    while (length--)
    {
        *bytes++ = 0;
    }
}


bool loadNvsString(
    const char* key,
    char* output,
    size_t outputSize)
{
    preferences.begin("symbol", true);

    size_t storedLength =
        preferences.getString(key, output, outputSize);

    preferences.end();

    return storedLength > 0 &&
           storedLength < outputSize;
}

String loadSetting(const char* name)
{
    preferences.begin("symbol", true);

    String value =
        preferences.getString(name, "");

    preferences.end();

    return value;
}

bool loadPrivateKey(uint8_t privateKey[32])
{
    String key = loadSetting("privateKey");

    Serial.print("Private key length = ");
    Serial.println(key.length());

    if (key.length() != 64)
    {
        Serial.println("Private key length ERROR");
        key.clear();
        return false;
    }

    bool result =
        hexToBytes(
            key.c_str(),
            privateKey,
            32);

    Serial.print("hexToBytes = ");
    Serial.println(result ? "OK" : "ERROR");

    key.clear();

    return result;
}


String bytesToHex(
    const uint8_t* data,
    size_t length)
{
    const char* hex =
        "0123456789ABCDEF";

    String result;

    result.reserve(length * 2);

    for (size_t i = 0; i < length; i++)
    {
        result +=
            hex[(data[i] >> 4) & 0x0F];

        result +=
            hex[data[i] & 0x0F];
    }

    return result;
}


void writeU16LE(
    uint8_t* buffer,
    size_t& pos,
    uint16_t value)
{
    buffer[pos++] = value & 0xFF;
    buffer[pos++] = (value >> 8) & 0xFF;
}


void writeU32LE(
    uint8_t* buffer,
    size_t& pos,
    uint32_t value)
{
    buffer[pos++] = value & 0xFF;
    buffer[pos++] = (value >> 8) & 0xFF;
    buffer[pos++] = (value >> 16) & 0xFF;
    buffer[pos++] = (value >> 24) & 0xFF;
}


void writeU64LE(
    uint8_t* buffer,
    size_t& pos,
    uint64_t value)
{
    for (int i = 0; i < 8; i++)
    {
        buffer[pos++] =
            (uint8_t)(value & 0xFF);

        value >>= 8;
    }
}


// ============================================================
// Base32
// ============================================================

int base32Value(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';

    if (c >= '2' && c <= '7')
        return c - '2' + 26;

    return -1;
}


//
// Symbol address:
//
// 39 chars
//      ↓
// Base32 + '='
//      ↓
// 25 bytes
//      ↓
// first 24 bytes = catbuffer address
//

bool decodeSymbolAddress(
    const char* input,
    uint8_t output[24])
{
    String s(input);

    s.replace("-", "");
    s.replace(" ", "");
    s.trim();
    s.toUpperCase();

    if (s.length() != 39)
    {
        Serial.println("Invalid address length");
        return false;
    }

    uint32_t buffer = 0;
    int bits = 0;
    size_t out = 0;

    for (size_t i = 0;
         i < s.length();
         i++)
    {
        int value =
            base32Value(s[i]);

        if (value < 0)
        {
            Serial.println(
                "Invalid Base32 address");

            return false;
        }

        buffer =
            (buffer << 5) |
            value;

        bits += 5;

        while (bits >= 8)
        {
            bits -= 8;

            if (out >= 24)
                break;

            output[out++] =
                (buffer >> bits) & 0xFF;

            if (bits == 0)
                buffer = 0;
            else
                buffer &= ((1 << bits) - 1);
        }
    }

    if (out != 24)
    {
        Serial.println(
            "Address decode failed");

        return false;
    }

    // testnet address check
    if ((output[0] & 0xFE) !=
        TESTNET_NETWORK)
    {
        Serial.println(
            "Recipient is not testnet");

        return false;
    }

    return true;
}


// ============================================================
// HTTP GET JSON
// ============================================================

bool getJson(
    const String& path,
    JsonDocument& doc)
{
    WiFiClientSecure client;

    // testnet experiment
    client.setInsecure();

    HTTPClient http;

    String url =
        String(NODE_URL) + path;

    Serial.print("GET ");
    Serial.println(url);

    if (!http.begin(client, url))
        return false;

    int code =
        http.GET();

    if (code != 200)
    {
        Serial.print(
            "HTTP GET error: ");

        Serial.println(code);

        http.end();

        return false;
    }

    String payload =
        http.getString();

    http.end();

    Serial.println(payload);

    DeserializationError error =
        deserializeJson(
            doc,
            payload);

    if (error)
    {
        Serial.print(
            "JSON error: ");

        Serial.println(
            error.c_str());

        return false;
    }

    return true;
}


// ============================================================
// Get /node/info
// ============================================================

bool getNodeInfo()
{
    JsonDocument doc;

    if (!getJson(
            "/node/info",
            doc))
    {
        return false;
    }

    networkIdentifier =
        doc["networkIdentifier"] |
        0;

    const char* generationHash =
        doc["networkGenerationHashSeed"];

    if (!generationHash)
    {
        Serial.println(
            "generationHashSeed missing");

        return false;
    }

    if (!hexToBytes(
            generationHash,
            generationHashSeed,
            32))
    {
        Serial.println(
            "generationHashSeed invalid");

        return false;
    }

    Serial.print(
        "networkIdentifier = ");

    Serial.println(
        networkIdentifier);

    Serial.print(
        "generationHashSeed = ");

    Serial.println(
        bytesToHex(
            generationHashSeed,
            32));

    if (networkIdentifier !=
        TESTNET_NETWORK)
    {
        Serial.println(
            "ERROR: node is NOT testnet");

        return false;
    }

    return true;
}


// ============================================================
// Get /network/properties
// ============================================================

uint64_t parseHexWithApostrophe(
    const char* text)
{
    String s(text);

    s.replace("0x", "");
    s.replace("0X", "");
    s.replace("'", "");

    return strtoull(
        s.c_str(),
        nullptr,
        16);
}


bool getNetworkProperties()
{
    JsonDocument doc;

    if (!getJson(
            "/network/properties",
            doc))
    {
        return false;
    }

    const char* epoch =
        doc["network"]["epochAdjustment"];

    const char* mosaic =
        doc["chain"]["currencyMosaicId"];

    if (!epoch || !mosaic)
    {
        Serial.println(
            "network properties missing");

        return false;
    }

    String epochString(epoch);

    epochString.replace("s", "");
    epochString.replace("S", "");

    epochAdjustment =
        strtoull(
            epochString.c_str(),
            nullptr,
            10);

    currencyMosaicId =
        parseHexWithApostrophe(mosaic);

    Serial.print(
        "epochAdjustment = ");

    Serial.println(
        (unsigned long long)
            epochAdjustment);

    Serial.print(
        "currencyMosaicId = 0x");

    Serial.println(
        (unsigned long long)
            currencyMosaicId,
        HEX);

    return true;
}


// ============================================================
// Get network time
// ============================================================

uint64_t getUnixTime()
{
    return (uint64_t)time(nullptr);
}


bool getNetworkTimestamp(
    uint64_t& timestamp)
{
    JsonDocument doc;

    if (!getJson(
            "/node/time",
            doc))
    {
        return false;
    }

    // REST uint64 is represented as a
    // JSON string in modern Symbol REST.

    const char* receive =
        doc["communicationTimestamps"]
            ["receiveTimestamp"];

    if (!receive)
    {
        // fallback
        uint64_t numeric =
            doc["communicationTimestamps"]
               ["receiveTimestamp"] |
            0ULL;

        timestamp = numeric;

        return true;
    }

    timestamp =
        strtoull(
            receive,
            nullptr,
            10);

    return true;
}


// ============================================================
// Create TransferTransactionV1
// ============================================================
//
// messageなし
// mosaic 1個
//
// size = 176 bytes
//
// ============================================================

static const size_t TX_SIZE = 176;

bool buildTransfer(
    uint8_t tx[TX_SIZE],
    const uint8_t recipient[24],
    const uint8_t publicKey[32])
{
    memset(
        tx,
        0,
        TX_SIZE);

    size_t pos = 0;

    // --------------------------------------------------------
    // Size
    // --------------------------------------------------------

    writeU32LE(
        tx,
        pos,
        TX_SIZE);

    // reserved
    writeU32LE(
        tx,
        pos,
        0);

    // signature
    memset(
        tx + pos,
        0,
        64);

    pos += 64;

    // signer public key
    memcpy(
        tx + pos,
        publicKey,
        32);

    pos += 32;

    // reserved
    writeU32LE(
        tx,
        pos,
        0);

    // version
    tx[pos++] = 1;

    // network
    tx[pos++] =
        networkIdentifier;

    // type
    writeU16LE(
        tx,
        pos,
        TRANSFER_TYPE);

    // --------------------------------------------------------
    // deadline
    // --------------------------------------------------------

    uint64_t networkTimestamp;

    if (!getNetworkTimestamp(
            networkTimestamp))
    {
        return false;
    }

    uint64_t deadline =
        networkTimestamp +
        ((uint64_t)DEADLINE_SECONDS * 1000ULL);

    // --------------------------------------------------------
    // fee
    // --------------------------------------------------------

    uint64_t fee =
        (uint64_t)TX_SIZE *
        FEE_MULTIPLIER;

    writeU64LE(
        tx,
        pos,
        fee);

    writeU64LE(
        tx,
        pos,
        deadline);

    // --------------------------------------------------------
    // recipient
    // --------------------------------------------------------

    memcpy(
        tx + pos,
        recipient,
        24);

    pos += 24;

    // --------------------------------------------------------
    // message size
    // --------------------------------------------------------

    writeU16LE(
        tx,
        pos,
        0);

    // mosaics count
    tx[pos++] = 1;

    // reserved
    tx[pos++] = 0;

    // reserved
    writeU32LE(
        tx,
        pos,
        0);

    // --------------------------------------------------------
    // mosaic
    // --------------------------------------------------------

    writeU64LE(
        tx,
        pos,
        currencyMosaicId);

    // 1 XYM
    writeU64LE(
        tx,
        pos,
        TRANSFER_AMOUNT);

    if (pos != TX_SIZE)
    {
        Serial.print(
            "TX size mismatch: ");

        Serial.println(pos);

        return false;
    }

    return true;
}


// ============================================================
// Sign
// ============================================================

bool signTransaction(
    uint8_t tx[TX_SIZE],
    const uint8_t privateKey[32],
    const uint8_t publicKey[32])
{
    //
    // generationHashSeed
    // +
    // tx[108..end]
    //

    uint8_t signingData[
        32 + TX_SIZE - 108];

    memcpy(
        signingData,
        generationHashSeed,
        32);

    memcpy(
        signingData + 32,
        tx + 108,
        TX_SIZE - 108);

    uint8_t signature[64];

    Ed25519::sign(
        signature,
        privateKey,
        publicKey,
        signingData,
        sizeof(signingData));

    // signature -> offset 8
    memcpy(
        tx + 8,
        signature,
        64);

    return true;
}


// ============================================================
// Transaction hash
// ============================================================

void calculateTransactionHash(
    const uint8_t tx[TX_SIZE],
    uint8_t hash[32])
{
    SHA3_256 sha3;

    // signature
    sha3.update(
        tx + 8,
        64);

    // signer public key
    sha3.update(
        tx + 72,
        32);

    // generation hash
    sha3.update(
        generationHashSeed,
        32);

    // transaction data
    sha3.update(
        tx + 108,
        TX_SIZE - 108);

    sha3.finalize(
        hash,
        32);
}


// ============================================================
// Announce
// ============================================================

bool announce(
    const uint8_t tx[TX_SIZE])
{
    WiFiClientSecure client;

    client.setInsecure();

    HTTPClient http;

    String url =
        String(NODE_URL) +
        "/transactions";

    if (!http.begin(
            client,
            url))
    {
        return false;
    }

    http.addHeader(
        "Content-Type",
        "application/json");

    String payload =
        "{\"payload\":\"" +
        bytesToHex(
            tx,
            TX_SIZE) +
        "\"}";

    Serial.println(
        "Announcing transaction...");

    int code =
        http.PUT(payload);

    String response =
        http.getString();

    Serial.print(
        "HTTP = ");

    Serial.println(code);

    Serial.println(response);

    http.end();

    return code == 200 ||
           code == 202;
}


// ============================================================
// Check transaction status
// ============================================================

bool waitForConfirmation(
    const uint8_t hash[32])
{
    String hashString =
        bytesToHex(
            hash,
            32);

    Serial.print(
        "TX hash = ");

    Serial.println(
        hashString);

    for (int i = 0; i < 30; i++)
    {
        delay(2000);

        JsonDocument doc;

        if (!getJson(
                "/transactionStatus/" +
                hashString,
                doc))
        {
            Serial.println(
                "status not found yet");

            continue;
        }

        const char* group =
            doc["group"];

        const char* code =
            doc["code"];

        Serial.print(
            "group=");

        Serial.println(
            group ? group : "?");

        Serial.print(
            "code=");

        Serial.println(
            code ? code : "?");

        if (group &&
            strcmp(group, "confirmed") == 0)
        {
            if (code &&
                strcmp(code, "Success") == 0)
            {
                return true;
            }

            Serial.println(
                "CONFIRMED but FAILED");

            return false;
        }

        if (group &&
            strcmp(group, "failed") == 0)
        {
            Serial.println(
                "TRANSACTION FAILED");

            return false;
        }
    }

    Serial.println(
        "Confirmation timeout");

    return false;
}


// ============================================================
// Send 1 XYM
// ============================================================

void sendOneXYM()
{
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);

    M5.Lcd.println("Symbol");
    M5.Lcd.println("1 XYM");
    M5.Lcd.println("sending...");

    // --------------------------------------------------------
    // Get network information
    // --------------------------------------------------------

    if (!getNodeInfo())
    {
        M5.Lcd.println("NODE ERROR");
        return;
    }

    if (!getNetworkProperties())
    {
        M5.Lcd.println("NETWORK ERROR");
        return;
    }

    // --------------------------------------------------------
    // Private key
    // --------------------------------------------------------

    uint8_t privateKey[32] = {};

    if (!loadPrivateKey(privateKey))
    {
        M5.Lcd.println(
            "PRIVATE KEY ERROR");

        return;
    }

    // --------------------------------------------------------
    // Public key
    // --------------------------------------------------------

    uint8_t publicKey[32];

    Ed25519::derivePublicKey(
        publicKey,
        privateKey);

    Serial.print(
        "Public key: ");

    Serial.println(
        bytesToHex(
            publicKey,
            32));

    // --------------------------------------------------------
    // Recipient
    // --------------------------------------------------------

    uint8_t recipient[24];

    if (!decodeSymbolAddress(
            ACCOUNT_B_ADDRESS,
            recipient))
    {
        secureZero(privateKey, sizeof(privateKey));

        M5.Lcd.println(
            "ADDRESS ERROR");

        return;
    }

    // network consistency
    if ((recipient[0] & 0xFE) !=
        networkIdentifier)
    {
        secureZero(privateKey, sizeof(privateKey));

        Serial.println(
            "Network mismatch!");

        M5.Lcd.println(
            "NETWORK MISMATCH");

        return;
    }

    // --------------------------------------------------------
    // Build
    // --------------------------------------------------------

    uint8_t tx[TX_SIZE];

    if (!buildTransfer(
            tx,
            recipient,
            publicKey))
    {
        secureZero(privateKey, sizeof(privateKey));

        M5.Lcd.println(
            "BUILD ERROR");

        return;
    }

    Serial.println(
        "Transaction built.");

    // --------------------------------------------------------
    // Sign
    // --------------------------------------------------------

    if (!signTransaction(
            tx,
            privateKey,
            publicKey))
    {
        secureZero(privateKey, sizeof(privateKey));

        M5.Lcd.println(
            "SIGN ERROR");

        return;
    }

    // The private key is no longer needed after signing.
    secureZero(privateKey, sizeof(privateKey));

    // --------------------------------------------------------
    // Verify our own signature
    // --------------------------------------------------------

    uint8_t signingData[
        32 + TX_SIZE - 108];

    memcpy(
        signingData,
        generationHashSeed,
        32);

    memcpy(
        signingData + 32,
        tx + 108,
        TX_SIZE - 108);

    bool valid =
        Ed25519::verify(
            tx + 8,
            publicKey,
            signingData,
            sizeof(signingData));

    if (!valid)
    {
        Serial.println(
            "LOCAL SIGNATURE VERIFY FAILED");

        M5.Lcd.println(
            "SIGN VERIFY ERR");

        return;
    }

    Serial.println(
        "Local signature verified.");

    // --------------------------------------------------------
    // Hash
    // --------------------------------------------------------

    uint8_t hash[32];

    calculateTransactionHash(
        tx,
        hash);

    String hashString =
        bytesToHex(
            hash,
            32);

    Serial.print(
        "Transaction hash: ");

    Serial.println(
        hashString);

    // --------------------------------------------------------
    // Announce
    // --------------------------------------------------------

    M5.Lcd.println(
        "announce...");

    if (!announce(tx))
    {
        M5.Lcd.println(
            "ANNOUNCE ERROR");

        return;
    }

    M5.Lcd.println(
        "accepted");

    // --------------------------------------------------------
    // Confirm
    // --------------------------------------------------------

    if (!waitForConfirmation(
            hash))
    {
        M5.Lcd.println(
            "TX FAILED");

        return;
    }

    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);

    M5.Lcd.println(
        "SUCCESS");

    M5.Lcd.println();

    M5.Lcd.println(
        "1 XYM");

    M5.Lcd.println(
        "confirmed!");

    Serial.println(
        "================================");

    Serial.println(
        "CONFIRMED / SUCCESS");

    Serial.println(
        hashString);

    Serial.println(
        "================================");
}


// ============================================================
// Setup
// ============================================================

void setup()
{
    M5.begin();

    Serial.begin(115200);

    M5.Lcd.setRotation(3);
    M5.Lcd.setTextSize(2);

    M5.Lcd.fillScreen(BLACK);

    M5.Lcd.setCursor(0, 0);

    M5.Lcd.println(
        "Symbol Testnet");

    // --------------------------------------------------------
    // WiFi
    // --------------------------------------------------------

    char wifiSsid[33] = {};
    char wifiPassword[65] = {};

    if (!loadNvsString(
            "ssid",
            wifiSsid,
            sizeof(wifiSsid)) ||
        !loadNvsString(
            "password",
            wifiPassword,
            sizeof(wifiPassword)))
    {
        M5.Lcd.println("NO WIFI CONFIG");
        Serial.println("WiFi credentials not found");

        secureZero(wifiSsid, sizeof(wifiSsid));
        secureZero(wifiPassword, sizeof(wifiPassword));

        return;
    }

    WiFi.begin(wifiSsid, wifiPassword);

    secureZero(wifiSsid, sizeof(wifiSsid));
    secureZero(wifiPassword, sizeof(wifiPassword));

    M5.Lcd.println();
    M5.Lcd.println(
        "WiFi...");

    Serial.print(
        "Connecting");

    while (
        WiFi.status() !=
        WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }

    Serial.println();

    Serial.println(
        "WiFi connected");

    Serial.println(
        WiFi.localIP());

    M5.Lcd.println(
        "Ready");

    M5.Lcd.println();
    M5.Lcd.println(
        "Press A");
}


// ============================================================
// Loop
// ============================================================

void loop()
{
    M5.update();

    if (M5.BtnA.wasPressed())
    {
        sendOneXYM();

        delay(1000);

        M5.Lcd.println();
        M5.Lcd.println(
            "Press A");
    }

    delay(20);
}
