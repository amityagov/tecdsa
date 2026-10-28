# TecdsaBench

SwiftUI-приложение для замеров клиентской части на iPhone. Сервер работает внутри приложения
(feature `bench-server` крейта `tecdsa-ffi`), сети нет. Доля клиента хранится в Keychain
(`KeychainStore`, `WhenUnlockedThisDeviceOnly`) — как в продуктовом сценарии.

Замеряется: проверка setup (гейт ≤ 4 с), keygen клиента (p99 ≤ 3 с), шаг клиента при подписи (≤ 150 мс),
размеры сообщений, серверные шаги (для справки), тепловое состояние. Отчёт можно скопировать или отправить кнопкой Share.

## Сборка и запуск

Нужны: Xcode, `xcodegen` (`brew install xcodegen`), rustup с таргетами
`aarch64-apple-ios` и `aarch64-apple-ios-sim`.

```sh
DEVELOPMENT_TEAM=XXXXXXXXXX ios/TecdsaBench/scripts/generate.sh   # биндинги + проект Xcode
open ios/TecdsaBench/TecdsaBench.xcodeproj                        # выбрать устройство, Run
```

Rust собирается pre-build-скриптом всегда в release (в debug цифры бессмысленны).
Для честных замеров: запускайте Release-конфигурацию (Product → Scheme → Edit Scheme → Run → Release),
телефон отключён от зарядки не обязателен, но уберите режим энергосбережения и дайте остыть
(в отчёте печатается `thermal state`).

Симулятор (проверка, что всё работает; цифры — это скорость Mac, не iPhone):

```sh
xcodebuild -project ios/TecdsaBench/TecdsaBench.xcodeproj -scheme TecdsaBench -sdk iphonesimulator \
  -configuration Release CODE_SIGN_IDENTITY=- CODE_SIGNING_ALLOWED=YES DEVELOPMENT_TEAM= build
xcrun simctl launch --console <UDID> com.amityagov.tecdsabench -autorun   # отчёт в stderr
```

Для Keychain в симуляторе сборка должна быть подписана (хотя бы ad-hoc), иначе `Storage`.

Каталог `Generated/` и проект `.xcodeproj` не коммитятся — создаются `generate.sh`.
