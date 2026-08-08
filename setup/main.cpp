#include <Arduino.h>
#include <Preferences.h>

Preferences preferences;

void setup()
{
    Serial.begin(115200);

    preferences.begin("symbol", false);

    preferences.putString(
        "ssid",
        "無線APのSSID名");

    preferences.putString(
        "password",
        "無線APのパスワード");

    preferences.putString(
        "privateKey",
        "アカウントAの秘密鍵");

    preferences.end();

    Serial.println("NVS saved.");
}

void loop()
{
}