# Nagram XF

A fork of [Nagram X](https://github.com/risin42/NagramX) with additional features.
Includes most features from exteraGram and AyuGram.

## Download

- [Telegram Channel](https://t.me/NagramX_Fork)
- [GitHub Releases](https://github.com/Keeperorowner/NagramXF/releases)

## Security Fixes

### Default AI Service

Replaced the hardcoded third-party proxy `chen-hai.ryzedns.org` with the official OpenAI API endpoint (`api.openai.com`). The AI feature requires a user-configured API key before any request is sent.

### Settings & passcodeHash Leak

- Removed `passcodeHash` / `passcodeType` / `autoLockIn` / `useFingerprint` from the settings backup scope
- Cloud sync (`NextAloneBot` storage) now excludes all API keys (`includeApiKeys=false`)

## Compilation Guide

### Local Build

1. Obtain API credentials (`TELEGRAM_APP_ID` and `TELEGRAM_APP_HASH`) from [Telegram Developer Portal](https://my.telegram.org/auth). Create `local.properties` in the project root with:

   ```properties
   TELEGRAM_APP_ID=<your_telegram_app_id>
   TELEGRAM_APP_HASH=<your_telegram_app_hash>
   ```

2. For APK signing: Replace `release.keystore` with your keystore and add signing configuration to `local.properties`:

   ```properties
   KEYSTORE_PASS=<your_keystore_password>
   ALIAS_NAME=<your_alias_name>
   ALIAS_PASS=<your_alias_password>
   ```

3. For FCM support: Replace `TMessagesProj/google-services.json` with your own configuration file.

4. Open the project in Android Studio to start building.

### GitHub Actions

The repository includes four CI workflows under `.github/workflows/`:

| Workflow | Branch | Trigger |
|----------|--------|---------|
| `canary.yml` | `canary` | Push / manual |
| `staging.yml` | `dev` | Push / manual |
| `release.yml` | `main` | Push / manual |
| `pr.yml` | any | Pull Request |

#### Required Secrets

Go to **Settings → Secrets and variables → Actions** and add:

| Secret | Description |
|--------|-------------|
| `LOCAL_PROPERTIES` | Base64-encoded build config (see format below) |

##### LOCAL_PROPERTIES Format

Base64 of a Java `.properties` file:

```properties
KEYSTORE_PASS=<keystore password>
ALIAS_NAME=<alias name>
ALIAS_PASS=<alias password>
TELEGRAM_APP_ID=<your Telegram API ID>
TELEGRAM_APP_HASH=<your Telegram API hash>
```

Generate with:

```bash
printf 'KEYSTORE_PASS=xxx\nALIAS_NAME=xxx\nALIAS_PASS=xxx\nTELEGRAM_APP_ID=12345\nTELEGRAM_APP_HASH=xxx\n' | base64 -w0
# PowerShell:
# [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('KEYSTORE_PASS=xxx...'))
```

#### Optional Upload Secrets

To publish APKs to a Telegram channel via a bot, configure these. Without them the build still succeeds — the upload job is skipped automatically:

| Secret | Description |
|--------|-------------|
| `HELPER_BOT_TOKEN` | Bot token from [@BotFather](https://t.me/BotFather) |
| `HELPER_BOT_CANARY_TARGET` | Chat/channel ID for canary uploads |
| `HELPER_BOT_TARGET` | Chat/channel ID for staging & release uploads |
| `APP_ID` | Telegram API ID (used by upload script) |
| `APP_HASH` | Telegram API hash (used by upload script) |

## Acknowledgments

- [NagramX](https://github.com/risin42/NagramX)
- [AyuGram](https://github.com/AyuGram/AyuGram4A)
- [Cherrygram](https://github.com/arsLan4k1390/Cherrygram)
- [exteraGram](https://github.com/exteraSquad/exteraGram)
- [OctoGram](https://github.com/OctoGramApp/OctoGram)
