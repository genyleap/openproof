pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import OpenProof.Demo

ApplicationWindow {
    id: window

    property string configuredBaseUrl: "https://127.0.0.1:18443"
    property string configuredCaCertificate: ""
    property string configuredDemoSubject: ""
    property string configuredDemoPassword: ""
    property string configuredPortalUrl: ""
    property string configuredOauthClientId: ""
    property string configuredFarcasterRelayUrl: "https://relay.farcaster.xyz/v1"
    property bool configuredRealAuthMode: false
    property bool configuredAutomaticProviderDiscovery: true
    property string configuredLanguage: "fa"
    property int pageIndex: 0
    property bool automaticLogin: false
    property bool isEnglish: configuredLanguage === "en"

    readonly property color ink: "#172033"
    readonly property color muted: "#667085"
    readonly property color accent: "#6558E8"
    readonly property color accentDark: "#5145CD"
    readonly property color success: "#0E7654"
    readonly property color canvas: "#F4F6FA"
    readonly property color line: "#E4E7EC"
    readonly property string uiFont: ".AppleSystemUIFont"
    readonly property int textAlignment: isEnglish ? Text.AlignLeft : Text.AlignRight
    readonly property var supportedRedirectProviders: ["google", "linkedin", "telegram", "github", "apple", "microsoft"]
    function t(fa, en) { return isEnglish ? en : fa }
    function providerLabel(provider) {
        const labels = {
            "google": "Google",
            "linkedin": "LinkedIn",
            "telegram": "Telegram",
            "farcaster": "Farcaster",
            "local": t("حساب OpenProof", "OpenProof account"),
            "password": t("رمز عبور OpenProof", "OpenProof password"),
            "github": "GitHub",
            "apple": "Apple",
            "microsoft": "Microsoft"
        }
        return labels[provider] || provider
    }
    function providerSymbol(provider) {
        const symbols = {
            "google": "language",
            "linkedin": "work",
            "telegram": "send",
            "farcaster": "alternate_email",
            "local": "shield_person",
            "password": "password",
            "github": "code",
            "apple": "phone_iphone",
            "microsoft": "window"
        }
        return symbols[provider] || "link"
    }
    function providerConnected(provider) {
        for (let index = 0; index < identity.connections.length; ++index) {
            if (identity.connections[index].provider === provider)
                return true
        }
        return false
    }

    width: 1180
    height: 790
    minimumWidth: 980
    minimumHeight: 680
    visible: true
    color: canvas
    title: "OpenProof — Identity Playground"

    FontLoader { id: iconFont; source: Qt.resolvedUrl("MaterialSymbolsRounded.ttf") }

    IdentityClient {
        id: identity
        objectName: "identityClient"
        baseUrl: window.configuredBaseUrl
        caCertificatePath: window.configuredCaCertificate
        oauthClientId: window.configuredOauthClientId
        farcasterRelayUrl: window.configuredFarcasterRelayUrl
        realAuthMode: window.configuredRealAuthMode
        english: window.isEnglish
    }

    Component.onCompleted: {
        if (window.configuredAutomaticProviderDiscovery)
            identity.refreshProviders()
    }

    Connections {
        target: identity

        function onTransactionChanged() {
            if (window.automaticLogin && identity.transactionId.length > 0) {
                window.automaticLogin = false
                identity.completeLogin(loginPassword.text, loginTotp.text)
            }
        }

        function onAuthenticatedChanged() {
            if (identity.authenticated) {
                window.pageIndex = 4
                identity.loadProfile()
            }
        }
    }

    component Surface: Rectangle {
        color: "#FFFFFF"
        radius: 16
        border.width: 1
        border.color: window.line
    }

    component Field: TextField {
        id: field
        implicitHeight: 48
        leftPadding: 14
        rightPadding: 14
        font.family: window.uiFont
        font.pixelSize: 14
        color: window.ink
        placeholderTextColor: "#98A2B3"
        selectionColor: window.accent
        selectedTextColor: "#FFFFFF"
        background: Rectangle {
            radius: 10
            color: field.activeFocus ? "#FFFFFF" : "#F9FAFB"
            border.width: field.activeFocus ? 2 : 1
            border.color: field.activeFocus ? window.accent : window.line
        }
    }

    component PrimaryButton: Button {
        id: primaryButton
        implicitHeight: 46
        leftPadding: 20
        rightPadding: 20
        font.family: window.uiFont
        font.pixelSize: 14
        font.bold: true
        contentItem: Text {
            text: primaryButton.text
            color: "#FFFFFF"
            font: primaryButton.font
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: 10
            color: primaryButton.down ? window.accentDark
                                      : (primaryButton.enabled ? window.accent : "#C7C3EE")
        }
    }

    component GhostButton: Button {
        id: ghostButton
        implicitHeight: 44
        leftPadding: 18
        rightPadding: 18
        font.family: window.uiFont
        font.pixelSize: 14
        font.bold: true
        contentItem: Text {
            text: ghostButton.text
            color: ghostButton.enabled ? window.ink : "#98A2B3"
            font: ghostButton.font
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: 10
            color: ghostButton.down ? "#EAECF0" : "#FFFFFF"
            border.width: 1
            border.color: window.line
        }
    }

    component NavButton: Button {
        id: navButton
        property string symbol: ""
        property int targetPage: 0
        property bool selected: window.pageIndex === targetPage

        Layout.fillWidth: true
        implicitHeight: 48
        leftPadding: 14
        rightPadding: 14
        onClicked: window.pageIndex = targetPage
        contentItem: RowLayout {
            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
            spacing: 12
            Rectangle {
                Layout.preferredWidth: 30
                Layout.preferredHeight: 30
                radius: 9
                color: navButton.selected ? "#8276F3" : "#27324A"
                Text {
                    anchors.centerIn: parent
                    text: navButton.symbol
                    color: "#FFFFFF"
                    font.family: iconFont.name
                    font.pixelSize: 20
                }
            }
            Text {
                Layout.fillWidth: true
                text: navButton.text
                color: navButton.selected ? "#FFFFFF" : "#B8C0D4"
                horizontalAlignment: window.textAlignment
                verticalAlignment: Text.AlignVCenter
                font.family: window.uiFont
                font.pixelSize: 14
                font.bold: navButton.selected
            }
        }
        background: Rectangle {
            radius: 11
            color: navButton.selected ? "#2C3650" : (navButton.hovered ? "#202B42" : "transparent")
        }
    }

    component PageTitle: ColumnLayout {
        id: pageTitle
        property string title: ""
        property string subtitle: ""
        Layout.fillWidth: true
        spacing: 5
        Text {
            Layout.fillWidth: true
            text: pageTitle.title
            horizontalAlignment: window.textAlignment
            color: window.ink
            font.family: window.uiFont
            font.pixelSize: 27
            font.bold: true
        }
        Text {
            Layout.fillWidth: true
            text: pageTitle.subtitle
            horizontalAlignment: window.textAlignment
            color: window.muted
            font.family: window.uiFont
            font.pixelSize: 14
        }
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0
        layoutDirection: window.isEnglish ? Qt.RightToLeft : Qt.LeftToRight

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: window.canvas

            ColumnLayout {
                anchors.fill: parent
                spacing: 0

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 76
                    color: "#FFFFFF"
                    border.width: 1
                    border.color: window.line

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 30
                        anchors.rightMargin: 30
                        spacing: 14
                        layoutDirection: window.isEnglish ? Qt.RightToLeft : Qt.LeftToRight

                        GhostButton {
                            text: window.t("نمایش پاسخ API", "View API response")
                            enabled: identity.responseText.length > 0
                            onClicked: responsePopup.open()
                        }
                        Item { Layout.fillWidth: true }
                        ColumnLayout {
                            spacing: 2
                            Text {
                                text: window.isEnglish ? ["Overview", "Farcaster", "Sign in", "Sign up", "Profile", "Connected accounts", "Connection"][window.pageIndex] : ["نمای کلی", "Farcaster", "ورود", "ثبت‌نام", "پروفایل", "حساب‌های متصل", "تنظیمات اتصال"][window.pageIndex]
                                color: window.ink
                                font.family: window.uiFont
                                font.pixelSize: 17
                                font.bold: true
                                horizontalAlignment: window.textAlignment
                                Layout.fillWidth: true
                            }
                            Text {
                                text: identity.busy ? window.t("در حال ارتباط با OpenProof…", "Connecting to OpenProof…") : identity.statusMessage
                                color: identity.lastRequestSucceeded ? window.success : window.muted
                                font.family: window.uiFont
                                font.pixelSize: 12
                                horizontalAlignment: window.textAlignment
                                Layout.maximumWidth: 500
                                elide: Text.ElideRight
                            }
                        }
                        Rectangle {
                            Layout.preferredWidth: 38
                            Layout.preferredHeight: 38
                            radius: 12
                            color: identity.busy ? "#FFF4D6"
                                                 : (identity.authenticated ? "#DDF7EC" : "#EEF0F5")
                            BusyIndicator {
                                anchors.centerIn: parent
                                width: 24
                                height: 24
                                running: identity.busy
                                visible: running
                            }
                            Text {
                                anchors.centerIn: parent
                                visible: !identity.busy
                                text: identity.authenticated ? "✓" : "•"
                                color: identity.authenticated ? window.success : window.muted
                                font.pixelSize: 21
                                font.bold: true
                            }
                        }
                    }
                }

                StackLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    currentIndex: window.pageIndex

                    ScrollView {
                        contentWidth: availableWidth
                        clip: true
                        ColumnLayout {
                            width: parent.width - 60
                            anchors.horizontalCenter: parent.horizontalCenter
                            spacing: 18
                            y: 28

                            PageTitle {
                                title: window.t("آزمایشگاه هویت OpenProof", "OpenProof Identity Playground")
                                subtitle: window.t("یک کلاینت واقعی برای آزمایش اتصال، ورود، session و پروفایل", "A real client for testing connectivity, login, sessions and profiles")
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 184
                                radius: 18
                                gradient: Gradient {
                                    orientation: Gradient.Horizontal
                                    GradientStop { position: 0.0; color: "#6558E8" }
                                    GradientStop { position: 1.0; color: "#8A6CF0" }
                                }
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 26
                                    spacing: 20
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 10
                                        Text {
                                            Layout.fillWidth: true
                                            text: window.t("هسته احراز هویت آماده تست است", "Your identity core is ready to test")
                                            horizontalAlignment: window.textAlignment
                                            color: "#FFFFFF"
                                            font.family: window.uiFont
                                            font.pixelSize: 24
                                            font.bold: true
                                        }
                                        Text {
                                            Layout.fillWidth: true
                                            text: window.t("با حساب آزمایشی وارد شوید، پروفایل را بخوانید و session را باطل کنید.", "Sign in with the demo account, load the profile and revoke the session.")
                                            horizontalAlignment: window.textAlignment
                                            color: "#EAE7FF"
                                            font.family: window.uiFont
                                            font.pixelSize: 14
                                            wrapMode: Text.Wrap
                                        }
                                        RowLayout {
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            PrimaryButton {
                                                id: startLoginButton
                                                text: window.t("شروع تست ورود", "Start login test")
                                                onClicked: window.pageIndex = 2
                                                background: Rectangle { radius: 10; color: startLoginButton.down ? "#E8E5FF" : "#FFFFFF" }
                                                contentItem: Text {
                                                    text: startLoginButton.text
                                                    color: window.accentDark
                                                    font: startLoginButton.font
                                                    horizontalAlignment: Text.AlignHCenter
                                                    verticalAlignment: Text.AlignVCenter
                                                }
                                            }
                                            Button {
                                                id: healthButton
                                                text: window.t("بررسی اتصال", "Check connection")
                                                enabled: !identity.busy
                                                implicitHeight: 46
                                                leftPadding: 18
                                                rightPadding: 18
                                                onClicked: identity.checkHealth()
                                                contentItem: Text {
                                                    text: healthButton.text
                                                    color: "#FFFFFF"
                                                    font.family: window.uiFont
                                                    font.bold: true
                                                    horizontalAlignment: Text.AlignHCenter
                                                    verticalAlignment: Text.AlignVCenter
                                                }
                                                background: Rectangle {
                                                    radius: 10
                                                    color: healthButton.down ? "#6759CF" : "#776BE0"
                                                    border.width: 1
                                                    border.color: "#A79DF5"
                                                }
                                            }
                                        }
                                    }
                                    Rectangle {
                                        Layout.preferredWidth: 104
                                        Layout.preferredHeight: 104
                                        radius: 32
                                        color: "#25FFFFFF"
                                        border.width: 1
                                        border.color: "#45FFFFFF"
                                        Text {
                                            anchors.centerIn: parent
                                            text: "OP"
                                            color: "#FFFFFF"
                                            font.family: window.uiFont
                                            font.pixelSize: 32
                                            font.bold: true
                                        }
                                    }
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 14
                                Repeater {
                                    model: window.isEnglish ? [
                                        {value: "TLS", label: "Verified transport", tone: "#0E7654", bg: "#E8F8F1"},
                                        {value: "2-Step", label: "Secure login", tone: "#6558E8", bg: "#EEECFF"},
                                        {value: "Cookie", label: "Real session", tone: "#B4690E", bg: "#FFF4DB"}
                                    ] : [
                                        {value: "TLS", label: "ارتباط معتبر", tone: "#0E7654", bg: "#E8F8F1"},
                                        {value: "2-Step", label: "ورود امن", tone: "#6558E8", bg: "#EEECFF"},
                                        {value: "Cookie", label: "session واقعی", tone: "#B4690E", bg: "#FFF4DB"}
                                    ]
                                    delegate: Surface {
                                        id: metricCard
                                        required property var modelData
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: 112
                                        ColumnLayout {
                                            anchors.fill: parent
                                            anchors.margins: 18
                                            spacing: 7
                                            Rectangle {
                                                Layout.preferredWidth: 52
                                                Layout.preferredHeight: 28
                                                radius: 8
                                                color: metricCard.modelData.bg
                                                Text {
                                                    anchors.centerIn: parent
                                                    text: metricCard.modelData.value
                                                    color: metricCard.modelData.tone
                                                    font.family: window.uiFont
                                                    font.pixelSize: 12
                                                    font.bold: true
                                                }
                                            }
                                            Text {
                                                Layout.fillWidth: true
                                                text: metricCard.modelData.label
                                                horizontalAlignment: window.textAlignment
                                                color: window.ink
                                                font.family: window.uiFont
                                                font.pixelSize: 15
                                                font.bold: true
                                            }
                                        }
                                    }
                                }
                            }

                            Surface {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 122
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 20
                                    spacing: 18
                                    RowLayout {
                                        spacing: 8
                                        GhostButton {
                                            text: window.t("ابزارهای تحت وب", "Web developer tools")
                                            enabled: window.configuredPortalUrl.length > 0
                                            onClicked: Qt.openUrlExternally(window.configuredPortalUrl)
                                        }
                                        GhostButton { text: window.t("تنظیمات", "Settings"); onClicked: window.pageIndex = 6 }
                                    }
                                    Item { Layout.fillWidth: true }
                                    ColumnLayout {
                                        spacing: 5
                                        Text { Layout.fillWidth: true; text: window.t("سرویس محلی", "Local service"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 16; font.bold: true }
                                        Text { Layout.fillWidth: true; text: identity.baseUrl; horizontalAlignment: Text.AlignRight; color: window.muted; font.family: "Menlo"; font.pixelSize: 12 }
                                    }
                                    Rectangle {
                                        Layout.preferredWidth: 48
                                        Layout.preferredHeight: 48
                                        radius: 14
                                        color: "#E8F8F1"
                                        Text { anchors.centerIn: parent; text: "✓"; color: window.success; font.pixelSize: 22; font.bold: true }
                                    }
                                }
                            }
                        }
                    }

                    ScrollView {
                        contentWidth: availableWidth
                        clip: true
                        Item {
                            width: parent.width
                            implicitHeight: farcasterColumn.implicitHeight + 56
                            ColumnLayout {
                                id: farcasterColumn
                                width: Math.min(parent.width - 60, 900)
                                anchors.horizontalCenter: parent.horizontalCenter
                                anchors.top: parent.top
                                anchors.topMargin: 28
                                spacing: 16

                                PageTitle {
                                    title: window.t("ورود با Farcaster", "Sign in with Farcaster")
                                    subtitle: identity.realAuthMode
                                        ? window.t("تأیید حساب شخصی با Relay رسمی و رجیستری زنده Optimism", "Verify your account through the official relay and live Optimism registry")
                                        : window.t("حالت فعلی شبیه‌سازی محلی و قطعی است؛ برای حساب شخصی real-auth را فعال کنید", "This is the deterministic local simulation; enable real-auth for your account")
                                }

                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 150
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 20
                                        spacing: 14
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            Rectangle {
                                                Layout.preferredWidth: 48
                                                Layout.preferredHeight: 48
                                                radius: 14
                                                color: window.accent
                                                Text { anchors.centerIn: parent; text: "F"; color: "#FFFFFF"; font.family: window.uiFont; font.pixelSize: 23; font.bold: true }
                                            }
                                            ColumnLayout {
                                                Layout.fillWidth: true
                                                spacing: 3
                                                Text { Layout.fillWidth: true; text: "SIGN IN WITH FARCASTER"; color: window.accent; font.family: window.uiFont; font.pixelSize: 11; font.bold: true; horizontalAlignment: window.textAlignment }
                                                Text { Layout.fillWidth: true; text: window.t("OpenProof کلید خصوصی را نمی‌گیرد؛ تأیید را در اپ Farcaster انجام می‌دهید.", "OpenProof never receives a private key; approval happens in your Farcaster app."); color: window.ink; font.family: window.uiFont; font.pixelSize: 16; font.bold: true; horizontalAlignment: window.textAlignment; wrapMode: Text.Wrap }
                                            }
                                            Rectangle {
                                                Layout.preferredWidth: 116
                                                Layout.preferredHeight: 32
                                                radius: 16
                                                color: identity.realAuthMode ? "#E7F7F0" : "#FFF4DB"
                                                Text { anchors.centerIn: parent; text: identity.realAuthMode ? window.t("حساب واقعی", "REAL ACCOUNT") : window.t("شبیه‌سازی", "SIMULATION"); color: identity.realAuthMode ? window.success : "#B4690E"; font.family: window.uiFont; font.pixelSize: 11; font.bold: true }
                                            }
                                        }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: Qt.LeftToRight
                                            spacing: 8
                                            Repeater {
                                                model: [["hub", "FIP-11"], ["link", "Optimism · 10"], ["tag", identity.farcasterFid.length ? "FID " + identity.farcasterFid : (identity.realAuthMode ? "Your FID" : "FID 6841")], ["verified_user", identity.realAuthMode ? "live registry" : (identity.farcasterSignerKind.length ? identity.farcasterSignerKind : "mock registry")]]
                                                delegate: Rectangle {
                                                    id: farcasterMetric
                                                    required property var modelData
                                                    Layout.fillWidth: true
                                                    Layout.preferredHeight: 38
                                                    radius: 9
                                                    color: "#F8F9FC"
                                                    border.width: 1
                                                    border.color: window.line
                                                    RowLayout {
                                                        anchors.fill: parent
                                                        anchors.leftMargin: 10
                                                        anchors.rightMargin: 10
                                                        spacing: 6
                                                        Text { text: farcasterMetric.modelData[0]; color: window.accent; font.family: iconFont.name; font.pixelSize: 16 }
                                                        Text { Layout.fillWidth: true; text: farcasterMetric.modelData[1]; color: window.ink; font.family: "Menlo"; font.pixelSize: 10; elide: Text.ElideRight }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 230
                                    visible: identity.realAuthMode
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 22
                                        spacing: 12
                                        Text { Layout.fillWidth: true; text: window.t("حساب شخصی‌تان را متصل کنید", "Connect your personal account"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 19; font.bold: true }
                                        Text { Layout.fillWidth: true; text: window.t("یک کانال کوتاه‌عمر ساخته می‌شود، مرورگر سیستم صفحهٔ تأیید را باز می‌کند و امضای برگشتی در OpenProof دوباره با رجیستری اصلی بررسی می‌شود.", "A short-lived channel is created, the system browser opens approval, and OpenProof verifies the returned signature again against the live registry."); horizontalAlignment: window.textAlignment; color: window.muted; font.family: window.uiFont; font.pixelSize: 12; wrapMode: Text.Wrap }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            PrimaryButton {
                                                text: identity.externalAuthActive ? window.t("منتظر تأیید در Farcaster…", "Waiting for Farcaster approval…") : window.t("ورود واقعی با Farcaster", "Sign in with Farcaster")
                                                enabled: !identity.busy && !identity.externalAuthActive
                                                onClicked: identity.signInWithFarcaster()
                                            }
                                            GhostButton { text: window.t("لغو", "Cancel"); visible: identity.externalAuthActive; enabled: !identity.busy; onClicked: identity.cancelExternalAuth() }
                                            GhostButton { text: window.t("بازکردن دوباره صفحهٔ تأیید", "Reopen approval"); visible: identity.farcasterConnectUrl.length > 0; onClicked: Qt.openUrlExternally(identity.farcasterConnectUrl) }
                                            Item { Layout.fillWidth: true }
                                        }
                                        Text { Layout.fillWidth: true; text: window.t("هیچ seed phrase یا private key وارد این اپ نکنید.", "Never enter a seed phrase or private key into this app."); horizontalAlignment: window.textAlignment; color: window.success; font.family: window.uiFont; font.pixelSize: 11; font.bold: true }
                                    }
                                }

                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 226
                                    visible: !identity.realAuthMode
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 20
                                        spacing: 11
                                        Text { Layout.fillWidth: true; text: window.t("۱. صدور چالش مستقیم", "1. Issue a direct challenge"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 18; font.bold: true }
                                        Text { Layout.fillWidth: true; text: window.t("دموی محلی از یک ERC-1271 قطعی استفاده می‌کند. برای محیط واقعی FID، آدرس و امضای کیف پول خودتان را وارد کنید.", "The local demo uses a deterministic ERC-1271 signer. In a real environment, enter your own FID, address, and wallet signature."); horizontalAlignment: window.textAlignment; color: window.muted; font.family: window.uiFont; font.pixelSize: 12; wrapMode: Text.Wrap }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: Qt.LeftToRight
                                            spacing: 10
                                            Field { id: farcasterFid; Layout.preferredWidth: 150; text: "6841"; placeholderText: "FID"; horizontalAlignment: Text.AlignLeft }
                                            Field { id: farcasterAddress; Layout.fillWidth: true; text: "0x1111111111111111111111111111111111111111"; placeholderText: "0x signer address"; horizontalAlignment: Text.AlignLeft; font.family: "Menlo"; font.pixelSize: 11 }
                                        }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            PrimaryButton { text: window.t("صدور پیام SIWF", "Issue SIWF message"); enabled: !identity.busy; onClicked: identity.beginFarcaster(farcasterFid.text, farcasterAddress.text) }
                                            GhostButton { text: window.t("پاک‌کردن", "Reset"); enabled: !identity.busy; onClicked: identity.resetFarcaster() }
                                            Item { Layout.fillWidth: true }
                                            Text { text: identity.farcasterExpiresAt; visible: text.length > 0; color: window.muted; font.family: "Menlo"; font.pixelSize: 9 }
                                        }
                                    }
                                }

                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 360
                                    visible: !identity.realAuthMode && identity.farcasterChallengeReady
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 20
                                        spacing: 10
                                        Text { Layout.fillWidth: true; text: window.t("۲. پیام دقیق را امضا و کامل کنید", "2. Sign the exact message and complete"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 18; font.bold: true }
                                        Rectangle {
                                            Layout.fillWidth: true
                                            Layout.preferredHeight: 190
                                            radius: 11
                                            color: "#101827"
                                            border.width: 1
                                            border.color: "#28344A"
                                            ScrollView {
                                                anchors.fill: parent
                                                clip: true
                                                TextArea { readOnly: true; selectByMouse: true; text: identity.farcasterMessage; color: "#D7DEEA"; font.family: "Menlo"; font.pixelSize: 10; wrapMode: TextEdit.WrapAnywhere; padding: 14; background: null }
                                            }
                                        }
                                        Field { id: farcasterSignature; Layout.fillWidth: true; text: "0x0102"; placeholderText: "0x signature"; horizontalAlignment: Text.AlignLeft; font.family: "Menlo"; font.pixelSize: 11 }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            PrimaryButton { text: window.t("تأیید SIWF و ساخت session", "Verify SIWF & issue session"); enabled: !identity.busy && identity.farcasterChallengeReady; onClicked: identity.completeFarcaster(farcasterSignature.text) }
                                            GhostButton { text: window.t("نمایش پاسخ", "View response"); enabled: identity.responseText.length > 0; onClicked: responsePopup.open() }
                                            Item { Layout.fillWidth: true }
                                            Text { text: identity.farcasterSignerKind.length ? identity.farcasterSignerKind : ""; color: window.success; font.family: "Menlo"; font.pixelSize: 11; font.bold: true }
                                        }
                                    }
                                }

                                GhostButton {
                                    Layout.alignment: Qt.AlignHCenter
                                    text: window.t("باز کردن Web Lab Farcaster", "Open Farcaster Web Lab")
                                    enabled: window.configuredPortalUrl.length > 0
                                    onClicked: Qt.openUrlExternally(window.configuredPortalUrl)
                                }
                            }
                        }
                    }

                    ScrollView {
                        contentWidth: availableWidth
                        clip: true
                        Item {
                            width: parent.width
                            implicitHeight: loginColumn.implicitHeight + 56
                            ColumnLayout {
                                id: loginColumn
                                width: Math.min(parent.width - 60, 720)
                                anchors.horizontalCenter: parent.horizontalCenter
                                anchors.top: parent.top
                                anchors.topMargin: 28
                                spacing: 18

                                PageTitle {
                                    title: window.t("ورود به OpenProof", "Sign in to OpenProof")
                                    subtitle: identity.realAuthMode
                                        ? window.t("با هر provider فعال وارد همان هویت canonical شوید، یا حساب disposable محلی را آزمایش کنید", "Use any enabled provider to reach the same canonical identity, or test the disposable local account")
                                        : window.t("این اجرا فقط حساب disposable محلی دارد؛ real-auth برای ارائه‌دهنده‌های واقعی لازم است", "This run has only a disposable local account; real-auth is required for live providers")
                                }
                                Surface {
                                    Layout.fillWidth: true
                                    implicitHeight: providerLoginColumn.implicitHeight + 40
                                    ColumnLayout {
                                        id: providerLoginColumn
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.top: parent.top
                                        anchors.margins: 20
                                        spacing: 11
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            Rectangle { Layout.preferredWidth: 42; Layout.preferredHeight: 42; radius: 13; color: "#EEECFF"; Text { anchors.centerIn: parent; text: "public"; color: window.accent; font.family: iconFont.name; font.pixelSize: 21 } }
                                            ColumnLayout {
                                                Layout.fillWidth: true
                                                spacing: 2
                                                Text { Layout.fillWidth: true; text: window.t("ارائه‌دهنده‌های ورود", "Sign-in providers"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 17; font.bold: true }
                                                Text { Layout.fillWidth: true; text: window.t("مرورگر سیستم + Authorization Code + PKCE؛ رمز provider هرگز به اپ داده نمی‌شود.", "System browser + Authorization Code + PKCE; provider passwords never reach the app."); horizontalAlignment: window.textAlignment; color: window.muted; font.family: window.uiFont; font.pixelSize: 11; wrapMode: Text.Wrap }
                                            }
                                            GhostButton { text: window.t("بررسی providerها", "Refresh providers"); enabled: !identity.busy && !identity.externalAuthActive; onClicked: identity.refreshProviders() }
                                        }
                                        Text {
                                            Layout.fillWidth: true
                                            visible: identity.redirectProviders.length === 0
                                            text: window.t("فعلاً هیچ providerی پیکربندی نشده است؛ گزینه‌ها پایین دیده می‌شوند ولی تا تنظیم CLIENT_ID و CLIENT_SECRET غیرفعال‌اند.", "No provider is configured yet; the supported options remain visible below but stay disabled until CLIENT_ID and CLIENT_SECRET are set.")
                                            horizontalAlignment: window.textAlignment
                                            color: window.muted
                                            font.family: window.uiFont
                                            font.pixelSize: 12
                                            wrapMode: Text.Wrap
                                        }
                                        Repeater {
                                            model: window.supportedRedirectProviders
                                            delegate: Rectangle {
                                                id: loginProviderRow
                                                required property string modelData
                                                readonly property bool providerAvailable: identity.redirectProviders.indexOf(modelData) !== -1
                                                Layout.fillWidth: true
                                                Layout.preferredHeight: 64
                                                radius: 12
                                                color: providerAvailable ? "#F9FAFB" : "#FBFBFC"
                                                border.width: 1
                                                border.color: window.line
                                                RowLayout {
                                                    anchors.fill: parent
                                                    anchors.margins: 10
                                                    layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                                    spacing: 11
                                                    Rectangle {
                                                        Layout.preferredWidth: 38
                                                        Layout.preferredHeight: 38
                                                        radius: 12
                                                        color: loginProviderRow.providerAvailable ? "#EEF0FF" : "#F0F1F4"
                                                        Text { anchors.centerIn: parent; text: window.providerSymbol(loginProviderRow.modelData); color: loginProviderRow.providerAvailable ? window.accent : window.muted; font.family: iconFont.name; font.pixelSize: 20 }
                                                    }
                                                    ColumnLayout {
                                                        Layout.fillWidth: true
                                                        spacing: 2
                                                        Text { text: window.providerLabel(loginProviderRow.modelData); color: window.ink; font.family: window.uiFont; font.pixelSize: 14; font.bold: true }
                                                        Text {
                                                            text: loginProviderRow.providerAvailable
                                                                ? window.t("آماده · Authorization Code + PKCE", "READY · Authorization Code + PKCE")
                                                                : window.t("نیازمند تنظیم credential سرور", "SERVER CREDENTIALS REQUIRED")
                                                            color: loginProviderRow.providerAvailable ? window.success : window.muted
                                                            font.family: "Menlo"
                                                            font.pixelSize: 9
                                                        }
                                                    }
                                                    PrimaryButton {
                                                        text: loginProviderRow.providerAvailable ? window.t("ورود", "Continue") : window.t("تنظیم نشده", "Not configured")
                                                        enabled: loginProviderRow.providerAvailable && !identity.busy && !identity.externalAuthActive
                                                        onClicked: identity.signInWithRedirectProvider(loginProviderRow.modelData)
                                                    }
                                                }
                                            }
                                        }
                                        GhostButton {
                                            Layout.alignment: window.isEnglish ? Qt.AlignLeft : Qt.AlignRight
                                            text: window.t("لغو ورود مرورگری", "Cancel browser sign-in")
                                            visible: identity.externalAuthActive
                                            enabled: !identity.busy
                                            onClicked: identity.cancelExternalAuth()
                                        }
                                    }
                                }
                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 430
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 24
                                        spacing: 12
                                        Rectangle {
                                            Layout.fillWidth: true
                                            Layout.preferredHeight: 54
                                            radius: 11
                                            color: "#EEECFF"
                                            RowLayout {
                                                anchors.fill: parent
                                                anchors.leftMargin: 14
                                                anchors.rightMargin: 14
                                                layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                                Text { text: window.t("حساب تست محلی", "Local test account"); color: window.accentDark; font.family: window.uiFont; font.bold: true }
                                                Item { Layout.fillWidth: true }
                                                Text { text: window.t("اطلاعات بعد از بستن اپ حذف می‌شوند", "Data is removed after the app closes"); color: window.muted; font.family: window.uiFont; font.pixelSize: 12 }
                                            }
                                        }
                                        Text { Layout.fillWidth: true; text: window.t("ایمیل یا subject", "Email or subject"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.bold: true }
                                        Field { id: loginSubject; Layout.fillWidth: true; text: window.configuredDemoSubject; placeholderText: "consumer@example.com"; horizontalAlignment: Text.AlignLeft; inputMethodHints: Qt.ImhEmailCharactersOnly }
                                        Text { Layout.fillWidth: true; text: window.t("رمز عبور", "Password"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.bold: true }
                                        Field { id: loginPassword; Layout.fillWidth: true; text: window.configuredDemoPassword; placeholderText: window.t("رمز عبور", "Password"); echoMode: TextInput.Password; horizontalAlignment: Text.AlignLeft }
                                        Field { id: loginTotp; Layout.fillWidth: true; placeholderText: window.t("کد TOTP — اختیاری", "TOTP code — optional"); inputMethodHints: Qt.ImhDigitsOnly }
                                        PrimaryButton {
                                            Layout.fillWidth: true
                                            text: identity.busy ? window.t("در حال ورود…", "Signing in…") : window.t("ورود امن به OpenProof", "Secure sign in to OpenProof")
                                            enabled: !identity.busy && loginSubject.text.length > 0 && loginPassword.text.length > 0
                                            onClicked: {
                                                window.automaticLogin = true
                                                identity.beginLogin(loginSubject.text)
                                            }
                                        }
                                        Text {
                                            Layout.fillWidth: true
                                            text: window.t("اپ transaction، challenge و cookieهای pre-auth را می‌گیرد و سپس رمز را در مرحله دوم ارسال می‌کند.", "The app preserves the transaction, challenge and pre-auth cookies, then submits the password in step two.")
                                            horizontalAlignment: Text.AlignHCenter
                                            color: window.muted
                                            font.family: window.uiFont
                                            font.pixelSize: 12
                                            wrapMode: Text.Wrap
                                        }
                                    }
                                }
                            }
                        }
                    }

                    ScrollView {
                        contentWidth: availableWidth
                        clip: true
                        ColumnLayout {
                            width: parent.width - 60
                            anchors.horizontalCenter: parent.horizontalCenter
                            spacing: 18
                            y: 28
                            PageTitle { title: window.t("ثبت‌نام و تأیید مالکیت", "Sign up & verify ownership"); subtitle: window.t("ساخت هویت جدید و تکمیل verification دریافت‌شده از delivery webhook", "Create an identity and complete the verification received from the delivery webhook") }
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 16
                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 392
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 22
                                        spacing: 11
                                        Text { Layout.fillWidth: true; text: window.t("ساخت حساب", "Create account"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 19; font.bold: true }
                                        Text { Layout.fillWidth: true; text: window.t("مرحله ۱", "STEP 1"); horizontalAlignment: window.textAlignment; color: window.accent; font.family: window.uiFont; font.pixelSize: 12; font.bold: true }
                                        Field { id: signupEmail; Layout.fillWidth: true; placeholderText: window.t("ایمیل", "Email"); horizontalAlignment: Text.AlignLeft }
                                        Field { id: signupName; Layout.fillWidth: true; placeholderText: window.t("نام نمایشی", "Display name"); horizontalAlignment: window.textAlignment }
                                        Field { id: signupPassword; Layout.fillWidth: true; placeholderText: window.t("رمز عبور طولانی", "Long password"); echoMode: TextInput.Password; horizontalAlignment: Text.AlignLeft }
                                        Item { Layout.fillHeight: true }
                                        PrimaryButton { Layout.fillWidth: true; text: window.t("ایجاد حساب", "Create account"); enabled: !identity.busy; onClicked: identity.signup(signupEmail.text, signupPassword.text, signupName.text) }
                                    }
                                }
                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 392
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 22
                                        spacing: 11
                                        Text { Layout.fillWidth: true; text: window.t("تأیید ایمیل", "Verify email"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 19; font.bold: true }
                                        Text { Layout.fillWidth: true; text: window.t("مرحله ۲", "STEP 2"); horizontalAlignment: window.textAlignment; color: window.accent; font.family: window.uiFont; font.pixelSize: 12; font.bold: true }
                                        Text { Layout.fillWidth: true; text: window.t("در محصول واقعی این دو مقدار از سرویس ارسال ایمیل یا پیامک دریافت می‌شوند.", "In production, these values arrive through your email or SMS delivery adapter."); horizontalAlignment: window.textAlignment; color: window.muted; font.family: window.uiFont; font.pixelSize: 12; wrapMode: Text.Wrap }
                                        Field { id: verificationId; Layout.fillWidth: true; placeholderText: "verification_id"; horizontalAlignment: Text.AlignLeft }
                                        Field { id: verificationSecret; Layout.fillWidth: true; placeholderText: "one-time secret"; horizontalAlignment: Text.AlignLeft }
                                        Item { Layout.fillHeight: true }
                                        GhostButton { Layout.fillWidth: true; text: window.t("تأیید و فعال‌سازی", "Verify & activate"); enabled: !identity.busy; onClicked: identity.verifyEmail(verificationId.text, verificationSecret.text) }
                                    }
                                }
                            }
                        }
                    }

                    ScrollView {
                        contentWidth: availableWidth
                        clip: true
                        Item {
                            width: parent.width
                            implicitHeight: profileColumn.implicitHeight + 56
                            ColumnLayout {
                                id: profileColumn
                                width: Math.min(parent.width - 60, 780)
                                anchors.horizontalCenter: parent.horizontalCenter
                                anchors.top: parent.top
                                anchors.topMargin: 28
                                spacing: 18
                                PageTitle { title: window.t("پروفایل canonical", "Canonical profile"); subtitle: identity.authenticated ? (identity.authenticationMethod === "google" ? window.t("پروفایل OpenProof با access token صادرشده برای کلاینت native", "OpenProof profile using the native client's access token") : window.t("پروفایل OpenProof با session امن داخل کلاینت", "OpenProof profile using the secure in-app session")) : window.t("برای دریافت پروفایل ابتدا وارد شوید", "Sign in before loading a profile") }
                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 164
                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.margins: 22
                                        spacing: 18
                                        GhostButton { text: window.t("دریافت مجدد", "Reload"); enabled: !identity.busy; onClicked: identity.loadProfile() }
                                        Item { Layout.fillWidth: true }
                                        ColumnLayout {
                                            spacing: 4
                                            Text { Layout.fillWidth: true; text: identity.authenticated ? window.t("کاربر وارد شده", "Signed-in user") : window.t("بدون session", "No session"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 18; font.bold: true }
                                            Text { Layout.fillWidth: true; text: identity.authenticated ? window.t("روش ورود: ", "Sign-in method: ") + identity.authenticationMethod : window.t("از صفحه ورود ادامه دهید", "Continue from the sign-in page"); horizontalAlignment: window.textAlignment; color: window.muted; font.family: window.uiFont; font.pixelSize: 13 }
                                        }
                                        Rectangle {
                                            Layout.preferredWidth: 72
                                            Layout.preferredHeight: 72
                                            radius: 24
                                            color: identity.authenticated ? "#DDF7EC" : "#EEF0F5"
                                            Text { anchors.centerIn: parent; text: identity.authenticated ? "✓" : "?"; color: identity.authenticated ? window.success : window.muted; font.pixelSize: 30; font.bold: true }
                                        }
                                    }
                                }
                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 116
                                    visible: identity.authenticated
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 20
                                        spacing: 8
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            Text { text: window.t("نام نمایشی", "Display name"); color: window.muted; font.family: window.uiFont; font.pixelSize: 11 }
                                            Text { Layout.fillWidth: true; text: identity.profileDisplayName.length ? identity.profileDisplayName : window.t("تنظیم نشده", "Not set"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 14; font.bold: true }
                                        }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            Text { text: window.t("ایمیل", "Email"); color: window.muted; font.family: window.uiFont; font.pixelSize: 11 }
                                            Text { Layout.fillWidth: true; text: identity.profileEmail.length ? identity.profileEmail : window.t("در این هویت ثبت نشده", "Not present on this identity"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: "Menlo"; font.pixelSize: 11; elide: Text.ElideMiddle }
                                            Text { visible: identity.profileEmail.length > 0; text: identity.profileEmailVerified ? window.t("تأییدشده", "VERIFIED") : window.t("تأییدنشده", "UNVERIFIED"); color: identity.profileEmailVerified ? window.success : "#B4690E"; font.family: window.uiFont; font.pixelSize: 9; font.bold: true }
                                        }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            Text { text: "identity_id"; color: window.muted; font.family: "Menlo"; font.pixelSize: 10 }
                                            Text { Layout.fillWidth: true; text: identity.profileIdentityId; horizontalAlignment: Text.AlignLeft; color: window.ink; font.family: "Menlo"; font.pixelSize: 10; elide: Text.ElideMiddle }
                                            Text { text: identity.profileLocale.length ? identity.profileLocale : "—"; color: window.accent; font.family: "Menlo"; font.pixelSize: 10 }
                                        }
                                    }
                                }
                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 116
                                    visible: identity.farcasterFid.length > 0
                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.margins: 20
                                        spacing: 14
                                        Rectangle { Layout.preferredWidth: 48; Layout.preferredHeight: 48; radius: 15; color: "#EEECFF"; Text { anchors.centerIn: parent; text: "F"; color: window.accent; font.family: window.uiFont; font.pixelSize: 22; font.bold: true } }
                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 3
                                            Text { Layout.fillWidth: true; text: identity.farcasterDisplayName.length ? identity.farcasterDisplayName : (identity.farcasterUsername.length ? "@" + identity.farcasterUsername : "FID " + identity.farcasterFid); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 17; font.bold: true }
                                            Text { Layout.fillWidth: true; text: (identity.farcasterUsername.length ? "@" + identity.farcasterUsername + " · " : "") + "FID " + identity.farcasterFid; horizontalAlignment: window.textAlignment; color: window.muted; font.family: "Menlo"; font.pixelSize: 11 }
                                        }
                                        Rectangle { Layout.preferredWidth: 124; Layout.preferredHeight: 32; radius: 16; color: "#E7F7F0"; Text { anchors.centerIn: parent; text: window.t("رجیستری تأیید شد", "REGISTRY VERIFIED"); color: window.success; font.family: window.uiFont; font.pixelSize: 9; font.bold: true } }
                                    }
                                }
                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 286
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 22
                                        spacing: 12
                                        Text { Layout.fillWidth: true; text: window.t("ویرایش پروفایل", "Edit profile"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 18; font.bold: true }
                                        Field { id: profileName; Layout.fillWidth: true; text: identity.profileDisplayName; placeholderText: window.t("نام نمایشی جدید", "New display name"); horizontalAlignment: window.textAlignment }
                                        Field { id: profileLocale; Layout.fillWidth: true; text: identity.profileLocale; placeholderText: "fa-IR"; horizontalAlignment: Text.AlignLeft }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            PrimaryButton { text: window.t("ذخیره تغییرات", "Save changes"); enabled: !identity.busy && identity.authenticated; onClicked: identity.updateProfile(profileName.text, profileLocale.text) }
                                            GhostButton { text: window.t("خروج از حساب", "Sign out"); enabled: !identity.busy && identity.authenticated; onClicked: identity.logout() }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    ScrollView {
                        contentWidth: availableWidth
                        clip: true
                        Item {
                            width: parent.width
                            implicitHeight: connectionsColumn.implicitHeight + 56
                            ColumnLayout {
                                id: connectionsColumn
                                width: Math.min(parent.width - 60, 860)
                                anchors.horizontalCenter: parent.horizontalCenter
                                anchors.top: parent.top
                                anchors.topMargin: 28
                                spacing: 18

                                PageTitle {
                                    title: window.t("حساب‌ها و روش‌های ورود", "Accounts & sign-in methods")
                                    subtitle: window.t("همهٔ providerها به همان هویت canonical متصل می‌شوند؛ حساب جدیدی ساخته نمی‌شود.", "Every provider connects to this same canonical identity; no second account is created.")
                                }

                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 144
                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.margins: 22
                                        spacing: 16
                                        layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                        Rectangle {
                                            Layout.preferredWidth: 62
                                            Layout.preferredHeight: 62
                                            radius: 20
                                            color: identity.authenticated ? "#EEECFF" : "#EEF0F5"
                                            Text {
                                                anchors.centerIn: parent
                                                text: identity.authenticated ? "shield_person" : "person_off"
                                                color: identity.authenticated ? window.accent : window.muted
                                                font.family: iconFont.name
                                                font.pixelSize: 30
                                            }
                                        }
                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 5
                                            Text {
                                                Layout.fillWidth: true
                                                text: identity.authenticated ? window.t("هویت اصلی شما", "Your primary identity") : window.t("ابتدا وارد شوید", "Sign in first")
                                                horizontalAlignment: window.textAlignment
                                                color: window.ink
                                                font.family: window.uiFont
                                                font.pixelSize: 18
                                                font.bold: true
                                            }
                                            Text {
                                                Layout.fillWidth: true
                                                text: identity.authenticated ? (identity.profileEmail.length ? identity.profileEmail : identity.profileIdentityId) : window.t("با حساب OpenProof، Google یا Farcaster وارد شوید؛ بعد providerهای دیگر را وصل کنید.", "Sign in with OpenProof, Google, or Farcaster, then connect other providers.")
                                                horizontalAlignment: identity.authenticated ? Text.AlignLeft : window.textAlignment
                                                color: window.muted
                                                font.family: identity.authenticated ? "Menlo" : window.uiFont
                                                font.pixelSize: identity.authenticated ? 11 : 13
                                                elide: Text.ElideMiddle
                                                wrapMode: identity.authenticated ? Text.NoWrap : Text.Wrap
                                            }
                                            Text {
                                                visible: identity.authenticated
                                                Layout.fillWidth: true
                                                text: window.t("ورود فعلی: ", "Current sign-in: ") + window.providerLabel(identity.authenticationMethod)
                                                horizontalAlignment: window.textAlignment
                                                color: window.success
                                                font.family: window.uiFont
                                                font.pixelSize: 11
                                                font.bold: true
                                            }
                                        }
                                        GhostButton {
                                            text: identity.authenticated ? window.t("تازه‌سازی", "Refresh") : window.t("رفتن به ورود", "Go to sign in")
                                            enabled: !identity.busy
                                            onClicked: {
                                                if (identity.authenticated)
                                                    identity.loadConnections()
                                                else
                                                    window.pageIndex = 2
                                            }
                                        }
                                    }
                                }

                                Surface {
                                    Layout.fillWidth: true
                                    visible: identity.authenticated
                                    implicitHeight: connectMethods.implicitHeight + 44
                                    ColumnLayout {
                                        id: connectMethods
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.top: parent.top
                                        anchors.margins: 22
                                        spacing: 11
                                        Text {
                                            Layout.fillWidth: true
                                            text: window.t("اتصال روش جدید", "Connect another method")
                                            horizontalAlignment: window.textAlignment
                                            color: window.ink
                                            font.family: window.uiFont
                                            font.pixelSize: 17
                                            font.bold: true
                                        }
                                        Text {
                                            Layout.fillWidth: true
                                            text: window.t("مرورگر فقط برای تأیید provider باز می‌شود؛ session یا token در URL قرار نمی‌گیرد.", "The browser opens only for provider approval; no session or token is placed in the URL.")
                                            horizontalAlignment: window.textAlignment
                                            color: window.muted
                                            font.family: window.uiFont
                                            font.pixelSize: 12
                                            wrapMode: Text.Wrap
                                        }

                                        Rectangle {
                                            Layout.fillWidth: true
                                            Layout.preferredHeight: 64
                                            radius: 12
                                            color: "#F9FAFB"
                                            border.width: 1
                                            border.color: window.line
                                            RowLayout {
                                                anchors.fill: parent
                                                anchors.margins: 10
                                                layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                                spacing: 11
                                                Rectangle {
                                                    Layout.preferredWidth: 38
                                                    Layout.preferredHeight: 38
                                                    radius: 12
                                                    color: "#EEECFF"
                                                    Text { anchors.centerIn: parent; text: "F"; color: window.accent; font.family: window.uiFont; font.pixelSize: 18; font.bold: true }
                                                }
                                                ColumnLayout {
                                                    Layout.fillWidth: true
                                                    spacing: 2
                                                    Text { text: "Farcaster"; color: window.ink; font.family: window.uiFont; font.pixelSize: 14; font.bold: true }
                                                    Text { text: window.t("تأیید FID با SIWF و رجیستری Optimism", "Verify the FID through SIWF and the Optimism registry"); color: window.muted; font.family: window.uiFont; font.pixelSize: 10 }
                                                }
                                                GhostButton {
                                                    text: window.providerConnected("farcaster") ? window.t("متصل", "Connected") : window.t("اتصال", "Connect")
                                                    enabled: !identity.busy && !identity.externalAuthActive && !window.providerConnected("farcaster")
                                                    onClicked: identity.connectFarcaster()
                                                }
                                            }
                                        }

                                        Repeater {
                                            model: identity.redirectProviders
                                            delegate: Rectangle {
                                                id: providerRow
                                                required property string modelData
                                                Layout.fillWidth: true
                                                Layout.preferredHeight: 64
                                                radius: 12
                                                color: "#F9FAFB"
                                                border.width: 1
                                                border.color: window.line
                                                RowLayout {
                                                    anchors.fill: parent
                                                    anchors.margins: 10
                                                    layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                                    spacing: 11
                                                    Rectangle {
                                                        Layout.preferredWidth: 38
                                                        Layout.preferredHeight: 38
                                                        radius: 12
                                                        color: "#EEF0FF"
                                                        Text {
                                                            anchors.centerIn: parent
                                                            text: window.providerSymbol(providerRow.modelData)
                                                            color: window.accent
                                                            font.family: iconFont.name
                                                            font.pixelSize: 20
                                                        }
                                                    }
                                                    ColumnLayout {
                                                        Layout.fillWidth: true
                                                        spacing: 2
                                                        Text { text: window.providerLabel(providerRow.modelData); color: window.ink; font.family: window.uiFont; font.pixelSize: 14; font.bold: true }
                                                        Text { text: window.t("احراز هویت استاندارد OIDC", "Standard OIDC authentication"); color: window.muted; font.family: window.uiFont; font.pixelSize: 10 }
                                                    }
                                                    GhostButton {
                                                        text: window.providerConnected(providerRow.modelData) ? window.t("متصل", "Connected") : window.t("اتصال", "Connect")
                                                        enabled: !identity.busy && !identity.externalAuthActive && !window.providerConnected(providerRow.modelData)
                                                        onClicked: identity.connectRedirectProvider(providerRow.modelData)
                                                    }
                                                }
                                            }
                                        }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            visible: identity.externalAuthActive
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            Text {
                                                Layout.fillWidth: true
                                                text: window.t("منتظر تأیید در مرورگر؛ پس از بازگشت فهرست خودکار تازه می‌شود.", "Waiting for browser approval; the list refreshes automatically when it completes.")
                                                horizontalAlignment: window.textAlignment
                                                color: window.success
                                                font.family: window.uiFont
                                                font.pixelSize: 11
                                                wrapMode: Text.Wrap
                                            }
                                            GhostButton { text: window.t("لغو", "Cancel"); enabled: !identity.busy; onClicked: identity.cancelExternalAuth() }
                                        }
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    visible: identity.authenticated
                                    spacing: 10
                                    RowLayout {
                                        Layout.fillWidth: true
                                        layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                        Text {
                                            Layout.fillWidth: true
                                            text: window.t("روش‌های ورود متصل", "Connected sign-in methods")
                                            horizontalAlignment: window.textAlignment
                                            color: window.ink
                                            font.family: window.uiFont
                                            font.pixelSize: 17
                                            font.bold: true
                                        }
                                        Rectangle {
                                            Layout.preferredWidth: 38
                                            Layout.preferredHeight: 26
                                            radius: 13
                                            color: "#EEECFF"
                                            Text { anchors.centerIn: parent; text: identity.connections.length; color: window.accent; font.family: window.uiFont; font.pixelSize: 11; font.bold: true }
                                        }
                                    }

                                    Surface {
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: 92
                                        visible: identity.connections.length === 0
                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.margins: 18
                                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                            Text { text: "sync"; color: window.accent; font.family: iconFont.name; font.pixelSize: 24 }
                                            Text { Layout.fillWidth: true; text: window.t("فهرس هنوز دریافت نشده؛ دکمهٔ تازه‌سازی را بزنید.", "The list has not been loaded yet; press Refresh."); horizontalAlignment: window.textAlignment; color: window.muted; font.family: window.uiFont; font.pixelSize: 12 }
                                        }
                                    }

                                    Repeater {
                                        model: identity.connections
                                        delegate: Surface {
                                            id: connectionRow
                                            required property var modelData
                                            Layout.fillWidth: true
                                            Layout.preferredHeight: 80
                                            RowLayout {
                                                anchors.fill: parent
                                                anchors.margins: 14
                                                spacing: 12
                                                layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                                                Rectangle {
                                                    Layout.preferredWidth: 44
                                                    Layout.preferredHeight: 44
                                                    radius: 14
                                                    color: "#EEECFF"
                                                    Text { anchors.centerIn: parent; text: window.providerSymbol(connectionRow.modelData.provider); color: window.accent; font.family: iconFont.name; font.pixelSize: 22 }
                                                }
                                                ColumnLayout {
                                                    Layout.fillWidth: true
                                                    spacing: 3
                                                    Text { Layout.fillWidth: true; text: window.providerLabel(connectionRow.modelData.provider); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.pixelSize: 14; font.bold: true }
                                                    Text { Layout.fillWidth: true; text: connectionRow.modelData.subject; horizontalAlignment: Text.AlignLeft; color: window.muted; font.family: "Menlo"; font.pixelSize: 10; elide: Text.ElideMiddle }
                                                }
                                                Rectangle {
                                                    Layout.preferredWidth: 86
                                                    Layout.preferredHeight: 28
                                                    radius: 14
                                                    color: "#E7F7F0"
                                                    Text { anchors.centerIn: parent; text: window.t("فعال", "ACTIVE"); color: window.success; font.family: window.uiFont; font.pixelSize: 9; font.bold: true }
                                                }
                                                GhostButton {
                                                    text: window.t("قطع", "Disconnect")
                                                    enabled: !identity.busy && identity.connections.length > 1
                                                    onClicked: identity.disconnectConnection(connectionRow.modelData.provider, connectionRow.modelData.subject)
                                                }
                                            }
                                        }
                                    }

                                    Text {
                                        Layout.fillWidth: true
                                        visible: identity.connections.length === 1
                                        text: window.t("آخرین روش ورود قابل قطع نیست. اول یک روش دیگر وصل کنید.", "The last sign-in method cannot be disconnected. Connect another method first.")
                                        horizontalAlignment: window.textAlignment
                                        color: "#B4690E"
                                        font.family: window.uiFont
                                        font.pixelSize: 11
                                        wrapMode: Text.Wrap
                                    }
                                }
                            }
                        }
                        onVisibleChanged: {
                            if (visible && identity.authenticated && !identity.busy)
                                identity.loadConnections()
                        }
                    }

                    ScrollView {
                        contentWidth: availableWidth
                        clip: true
                        Item {
                            width: parent.width
                            implicitHeight: settingsColumn.implicitHeight + 56
                            ColumnLayout {
                                id: settingsColumn
                                width: Math.min(parent.width - 60, 780)
                                anchors.horizontalCenter: parent.horizontalCenter
                                anchors.top: parent.top
                                anchors.topMargin: 28
                                spacing: 18
                                PageTitle { title: window.t("تنظیمات اتصال", "Connection settings"); subtitle: window.t("این مقادیر توسط launcher محلی وارد شده‌اند و معمولاً نیازی به تغییر ندارند", "The local launcher supplies these values; normally you do not need to change them") }
                                Surface {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 328
                                    ColumnLayout {
                                        anchors.fill: parent
                                        anchors.margins: 22
                                        spacing: 11
                                        Text { Layout.fillWidth: true; text: window.t("آدرس OpenProof", "OpenProof URL"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.bold: true }
                                        Field { id: baseUrl; Layout.fillWidth: true; text: window.configuredBaseUrl; horizontalAlignment: Text.AlignLeft; onEditingFinished: identity.baseUrl = text }
                                        Text { Layout.fillWidth: true; text: window.t("گواهی CA محلی", "Local CA certificate"); horizontalAlignment: window.textAlignment; color: window.ink; font.family: window.uiFont; font.bold: true }
                                        Field { id: caPath; Layout.fillWidth: true; text: window.configuredCaCertificate; horizontalAlignment: Text.AlignLeft; onEditingFinished: identity.caCertificatePath = text }
                                        Text { Layout.fillWidth: true; text: window.t("اعتبارسنجی TLS هیچ‌وقت خاموش نمی‌شود. HTTP فقط برای آدرس loopback پذیرفته است.", "TLS validation is never disabled. HTTP is accepted only for loopback addresses."); horizontalAlignment: window.textAlignment; color: window.muted; font.family: window.uiFont; font.pixelSize: 12; wrapMode: Text.Wrap }
                                        PrimaryButton {
                                            text: window.t("ذخیره و بررسی اتصال", "Save & check connection")
                                            enabled: !identity.busy
                                            onClicked: {
                                                identity.baseUrl = baseUrl.text
                                                identity.caCertificatePath = caPath.text
                                                identity.checkHealth()
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Rectangle {
            Layout.preferredWidth: 256
            Layout.fillHeight: true
            color: "#111A2E"

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 18
                spacing: 8

                RowLayout {
                    Layout.fillWidth: true
                    layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                    spacing: 12
                    Rectangle {
                        Layout.preferredWidth: 44
                        Layout.preferredHeight: 44
                        radius: 14
                        color: window.accent
                        Text { anchors.centerIn: parent; text: "OP"; color: "#FFFFFF"; font.family: window.uiFont; font.pixelSize: 16; font.bold: true }
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0
                        Text { Layout.fillWidth: true; text: "OpenProof"; horizontalAlignment: window.textAlignment; color: "#FFFFFF"; font.family: window.uiFont; font.pixelSize: 18; font.bold: true }
                        Text { Layout.fillWidth: true; text: "Identity Playground"; horizontalAlignment: window.textAlignment; color: "#7F8BA6"; font.family: window.uiFont; font.pixelSize: 11 }
                    }
                }

                Item { Layout.preferredHeight: 16 }
                Button {
                    id: languageButton
                    Layout.fillWidth: true
                    implicitHeight: 42
                    text: window.isEnglish ? "فارسی" : "English"
                    onClicked: window.isEnglish = !window.isEnglish
                    contentItem: RowLayout {
                        layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                        Text { text: "translate"; color: "#A99FF7"; font.family: iconFont.name; font.pixelSize: 19 }
                        Text { Layout.fillWidth: true; text: languageButton.text; color: "#D8DDEA"; font.family: window.uiFont; font.bold: true; horizontalAlignment: window.textAlignment }
                    }
                    background: Rectangle { radius: 10; color: languageButton.hovered ? "#202B42" : "#17223A"; border.width: 1; border.color: "#26334D" }
                }
                Item { Layout.preferredHeight: 4 }
                NavButton { text: window.t("نمای کلی", "Overview"); symbol: "dashboard"; targetPage: 0 }
                NavButton { text: window.t("ورود", "Sign in"); symbol: "password"; targetPage: 2 }
                NavButton { text: window.t("ثبت‌نام", "Sign up"); symbol: "person_add"; targetPage: 3 }
                NavButton { text: window.t("پروفایل", "Profile"); symbol: "account_circle"; targetPage: 4 }
                NavButton { text: window.t("حساب‌های متصل", "Connected accounts"); symbol: "linked_services"; targetPage: 5 }
                NavButton { text: "Farcaster"; symbol: "alternate_email"; targetPage: 1 }
                NavButton { text: window.t("تنظیمات اتصال", "Connection"); symbol: "settings"; targetPage: 6 }
                Item { Layout.fillHeight: true }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 106
                    radius: 14
                    color: "#19243B"
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 7
                        RowLayout {
                            Layout.fillWidth: true
                            layoutDirection: window.isEnglish ? Qt.LeftToRight : Qt.RightToLeft
                            Rectangle { Layout.preferredWidth: 10; Layout.preferredHeight: 10; radius: 5; color: identity.authenticated ? "#38D39F" : "#8590A6" }
                            Text { Layout.fillWidth: true; text: identity.authenticated ? window.t("session فعال", "Active session") : window.t("آماده تست", "Ready to test"); horizontalAlignment: window.textAlignment; color: "#E8ECF5"; font.family: window.uiFont; font.bold: true; font.pixelSize: 13 }
                        }
                        Text { Layout.fillWidth: true; text: identity.baseUrl; color: "#8793AA"; font.family: "Menlo"; font.pixelSize: 9; elide: Text.ElideMiddle; horizontalAlignment: Text.AlignLeft }
                        Text { Layout.fillWidth: true; text: window.t("محیط disposable محلی", "Disposable local environment"); horizontalAlignment: window.textAlignment; color: "#69758D"; font.family: window.uiFont; font.pixelSize: 10 }
                    }
                }
            }
        }
    }

    Popup {
        id: responsePopup
        anchors.centerIn: Overlay.overlay
        width: Math.min(window.width - 80, 760)
        height: Math.min(window.height - 100, 560)
        modal: true
        focus: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        padding: 0
        background: Rectangle { radius: 18; color: "#FFFFFF"; border.width: 1; border.color: window.line }
        contentItem: ColumnLayout {
            spacing: 0
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 66
                color: "transparent"
                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 20
                    anchors.rightMargin: 20
                    GhostButton { text: window.t("بستن", "Close"); onClicked: responsePopup.close() }
                    Item { Layout.fillWidth: true }
                    Text { text: window.t("پاسخ OpenProof API", "OpenProof API response"); color: window.ink; font.family: window.uiFont; font.pixelSize: 17; font.bold: true }
                }
            }
            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: window.line }
            ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true
                TextArea {
                    readOnly: true
                    text: identity.responseText
                    color: "#D6DAE5"
                    font.family: "Menlo"
                    font.pixelSize: 12
                    wrapMode: TextEdit.WrapAnywhere
                    padding: 20
                    background: Rectangle { color: "#101827" }
                }
            }
        }
    }
}
