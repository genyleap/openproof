#include "identityclient.h"

#include <QCryptographicHash>
#include <QDesktopServices>
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QNetworkCookieJar>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QTcpSocket>
#include <QUrl>
#include <QUrlQuery>

#include <algorithm>
#include <utility>

namespace {

[[nodiscard]] bool isLoopbackHost(const QString &host)
{
    if (host.compare(QStringLiteral("localhost"), Qt::CaseInsensitive) == 0) return true;
    QHostAddress address;
    return address.setAddress(host) && address.isLoopback();
}

[[nodiscard]] QString prettyBody(const QByteArray &body, bool english)
{
    if (body.isEmpty()) {
        return english ? QStringLiteral("(empty response body)")
                       : QStringLiteral("(بدون بدنه پاسخ)");
    }
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(body, &error);
    return error.error == QJsonParseError::NoError
        ? QString::fromUtf8(document.toJson(QJsonDocument::Indented))
        : QString::fromUtf8(body);
}

[[nodiscard]] QString apiErrorMessage(const QByteArray &body)
{
    const auto document = QJsonDocument::fromJson(body);
    if (!document.isObject()) return {};
    const auto object = document.object();
    const QString detail = object.value(QStringLiteral("message")).toString();
    return detail.isEmpty() ? object.value(QStringLiteral("error")).toString() : detail;
}

[[nodiscard]] QString randomBase64Url(int byteCount)
{
    QByteArray value(byteCount, Qt::Uninitialized);
    auto *generator = QRandomGenerator::system();
    for (int index = 0; index < value.size(); ++index) {
        value[index] = static_cast<char>(generator->bounded(256));
    }
    return QString::fromLatin1(value.toBase64(QByteArray::Base64UrlEncoding
                                               | QByteArray::OmitTrailingEquals));
}

[[nodiscard]] bool configureSsl(QNetworkRequest &request, const QString &caPath,
                                QString *error)
{
    if (request.url().scheme() != QStringLiteral("https") || caPath.isEmpty()) return true;
    QFile certificateFile(caPath);
    if (!certificateFile.open(QIODevice::ReadOnly)) {
        *error = QStringLiteral("The local CA file cannot be read.");
        return false;
    }
    const auto certificates = QSslCertificate::fromData(certificateFile.readAll());
    if (certificates.isEmpty()) {
        *error = QStringLiteral("The local CA file contains no valid PEM certificate.");
        return false;
    }
    auto ssl = QSslConfiguration::defaultConfiguration();
    auto authorities = ssl.caCertificates();
    authorities.append(certificates);
    ssl.setCaCertificates(authorities);
    request.setSslConfiguration(ssl);
    return true;
}

} // namespace

IdentityClient::IdentityClient(QObject *parent) : QObject(parent)
{
    m_network.setCookieJar(new QNetworkCookieJar(&m_network));
    m_farcasterPollTimer.setSingleShot(true);
    m_farcasterPollTimer.setInterval(1500);
    connect(&m_farcasterPollTimer, &QTimer::timeout, this, &IdentityClient::pollFarcasterRelay);
    m_connectionPollTimer.setSingleShot(true);
    m_connectionPollTimer.setInterval(1500);
    connect(&m_connectionPollTimer, &QTimer::timeout, this, [this] {
        if (!m_externalAuthActive || m_pendingConnectionProvider.isEmpty()) return;
        if (++m_connectionPollCount > 120) {
            cancelExternalAuth();
            setResult(false, message("مهلت اتصال provider تمام شد؛ دوباره تلاش کنید.",
                                     "Provider connection timed out; try again."));
            return;
        }
        if (m_busy) {
            m_connectionPollTimer.start();
            return;
        }
        loadConnections();
    });
    connect(&m_oauthListener, &QTcpServer::newConnection, this, &IdentityClient::acceptOAuthCallback);
}

QString IdentityClient::baseUrl() const { return m_baseUrl; }
QString IdentityClient::caCertificatePath() const { return m_caCertificatePath; }
QString IdentityClient::oauthClientId() const { return m_oauthClientId; }
QString IdentityClient::farcasterRelayUrl() const { return m_farcasterRelayUrl; }
bool IdentityClient::realAuthMode() const { return m_realAuthMode; }
bool IdentityClient::googleAvailable() const { return m_googleAvailable; }
QStringList IdentityClient::redirectProviders() const { return m_redirectProviders; }
QVariantList IdentityClient::connections() const { return m_connections; }
bool IdentityClient::externalAuthActive() const { return m_externalAuthActive; }
QString IdentityClient::authenticationMethod() const { return m_authenticationMethod; }
QString IdentityClient::profileIdentityId() const { return m_profileIdentityId; }
QString IdentityClient::profileDisplayName() const { return m_profileDisplayName; }
QString IdentityClient::profileEmail() const { return m_profileEmail; }
QString IdentityClient::profileLocale() const { return m_profileLocale; }
QString IdentityClient::profilePicture() const { return m_profilePicture; }
bool IdentityClient::profileEmailVerified() const { return m_profileEmailVerified; }
bool IdentityClient::busy() const { return m_busy; }
bool IdentityClient::authenticated() const { return m_authenticated; }
bool IdentityClient::lastRequestSucceeded() const { return m_lastRequestSucceeded; }
QString IdentityClient::statusMessage() const { return m_statusMessage; }
QString IdentityClient::responseText() const { return m_responseText; }
QString IdentityClient::transactionId() const { return m_transactionId; }
QString IdentityClient::challengeId() const { return m_challengeId; }
QString IdentityClient::farcasterMessage() const { return m_farcasterMessage; }
QString IdentityClient::farcasterNonce() const { return m_farcasterNonce; }
QString IdentityClient::farcasterSignerKind() const { return m_farcasterSignerKind; }
QString IdentityClient::farcasterExpiresAt() const { return m_farcasterExpiresAt; }
QString IdentityClient::farcasterConnectUrl() const { return m_farcasterConnectUrl; }
QString IdentityClient::farcasterFid() const { return m_farcasterFid; }
QString IdentityClient::farcasterUsername() const { return m_farcasterUsername; }
QString IdentityClient::farcasterDisplayName() const { return m_farcasterDisplayName; }
QString IdentityClient::farcasterPfpUrl() const { return m_farcasterPfpUrl; }
bool IdentityClient::farcasterChallengeReady() const { return !m_farcasterMessage.isEmpty(); }
bool IdentityClient::english() const { return m_english; }

void IdentityClient::setEnglish(bool value)
{
    if (m_english == value) return;
    m_english = value;
    if (!m_busy && !m_externalAuthActive) {
        m_statusMessage = message("آماده اتصال به OpenProof", "Ready to connect to OpenProof");
        emit statusMessageChanged();
    }
    emit languageChanged();
}

QString IdentityClient::message(const char *persian, const char *english) const
{
    return QString::fromUtf8(m_english ? english : persian);
}

void IdentityClient::setBaseUrl(const QString &value)
{
    QString normalized = value.trimmed();
    while (normalized.endsWith('/')) normalized.chop(1);
    if (m_baseUrl == normalized) return;
    cancelExternalAuth();
    m_baseUrl = normalized;
    m_network.setCookieJar(new QNetworkCookieJar(&m_network));
    clearOAuthTokens();
    applyProfile({});
    setAuthenticated(false);
    m_googleAvailable = false;
    m_redirectProviders.clear();
    emit providersChanged();
    m_connections.clear();
    emit connectionsChanged();
    resetFarcaster();
    emit baseUrlChanged();
}

void IdentityClient::setCaCertificatePath(const QString &value)
{
    const QString normalized = value.trimmed();
    if (m_caCertificatePath == normalized) return;
    m_caCertificatePath = normalized;
    emit caCertificatePathChanged();
}

void IdentityClient::setOauthClientId(const QString &value)
{
    const QString normalized = value.trimmed();
    if (m_oauthClientId == normalized) return;
    m_oauthClientId = normalized;
    emit oauthConfigurationChanged();
}

void IdentityClient::setFarcasterRelayUrl(const QString &value)
{
    QString normalized = value.trimmed();
    while (normalized.endsWith('/')) normalized.chop(1);
    if (m_farcasterRelayUrl == normalized) return;
    m_farcasterRelayUrl = normalized;
    emit farcasterConfigurationChanged();
}

void IdentityClient::setRealAuthMode(bool value)
{
    if (m_realAuthMode == value) return;
    m_realAuthMode = value;
    emit realAuthModeChanged();
}

void IdentityClient::setAuthenticationMethod(QString value)
{
    if (m_authenticationMethod == value) return;
    m_authenticationMethod = std::move(value);
    emit authenticationMethodChanged();
}

void IdentityClient::setExternalAuthActive(bool value)
{
    if (m_externalAuthActive == value) return;
    m_externalAuthActive = value;
    emit externalAuthChanged();
}

void IdentityClient::setBusy(bool value)
{
    if (m_busy == value) return;
    m_busy = value;
    emit busyChanged();
}

void IdentityClient::setAuthenticated(bool value)
{
    if (m_authenticated == value) return;
    m_authenticated = value;
    emit authenticatedChanged();
}

void IdentityClient::setResult(bool success, QString detail, QString response)
{
    if (m_lastRequestSucceeded != success) {
        m_lastRequestSucceeded = success;
        emit lastRequestSucceededChanged();
    }
    m_statusMessage = std::move(detail);
    m_responseText = std::move(response);
    emit statusMessageChanged();
    emit responseTextChanged();
}

void IdentityClient::clearOutput() { setResult(false, message("آماده", "Ready"), {}); }
void IdentityClient::checkHealth() { send(Operation::Health, "GET", QStringLiteral("/health/ready")); }
void IdentityClient::refreshProviders() { send(Operation::Providers, "GET", QStringLiteral("/auth/providers")); }

void IdentityClient::signup(const QString &email, const QString &password, const QString &displayName)
{
    if (email.trimmed().isEmpty() || password.isEmpty()) {
        setResult(false, message("ایمیل و رمز عبور الزامی‌اند.", "Email and password are required."));
        return;
    }
    QJsonObject body{{QStringLiteral("email"), email.trimmed()},
                     {QStringLiteral("password"), password}};
    if (!displayName.trimmed().isEmpty()) body.insert(QStringLiteral("display_name"), displayName.trimmed());
    send(Operation::Signup, "POST", QStringLiteral("/account/signup"), body);
}

void IdentityClient::verifyEmail(const QString &verificationId, const QString &secret)
{
    if (verificationId.trimmed().isEmpty() || secret.isEmpty()) {
        setResult(false, message("شناسه و secret تأیید الزامی‌اند.", "Verification ID and secret are required."));
        return;
    }
    send(Operation::VerifyEmail, "POST", QStringLiteral("/account/email/verify"),
         {{QStringLiteral("verification_id"), verificationId.trimmed()},
          {QStringLiteral("secret"), secret}});
}

void IdentityClient::beginLogin(const QString &subject)
{
    if (subject.trimmed().isEmpty()) {
        setResult(false, message("ایمیل/subject الزامی است.", "Email or subject is required."));
        return;
    }
    m_transactionId.clear();
    m_challengeId.clear();
    emit transactionChanged();
    send(Operation::BeginLogin, "POST", QStringLiteral("/auth/login"),
         {{QStringLiteral("subject"), subject.trimmed()}});
}

void IdentityClient::completeLogin(const QString &password, const QString &totp)
{
    if (m_transactionId.isEmpty() || m_challengeId.isEmpty()) {
        setResult(false, message("ابتدا مرحله «شروع ورود» را اجرا کنید.", "Run the start-login step first."));
        return;
    }
    if (password.isEmpty()) {
        setResult(false, message("رمز عبور الزامی است.", "Password is required."));
        return;
    }
    QJsonObject body{{QStringLiteral("transaction_id"), m_transactionId},
                     {QStringLiteral("challenge_id"), m_challengeId},
                     {QStringLiteral("password"), password}};
    if (!totp.trimmed().isEmpty()) body.insert(QStringLiteral("totp"), totp.trimmed());
    send(Operation::CompleteLogin, "POST", QStringLiteral("/auth/mfa/verify"), body);
}

void IdentityClient::beginFarcaster(const QString &fid, const QString &address)
{
    static const QRegularExpression addressPattern{QStringLiteral("^0x[0-9a-fA-F]{40}$")};
    bool validFid = false;
    const qulonglong parsedFid = fid.trimmed().toULongLong(&validFid, 10);
    if (!validFid || parsedFid == 0U || !addressPattern.match(address.trimmed()).hasMatch()) {
        setResult(false, message("یک FID غیرصفر و آدرس ۲۰ بایتی معتبر وارد کنید.",
                                 "Enter a non-zero FID and valid 20-byte address."));
        return;
    }
    resetFarcaster();
    send(Operation::BeginFarcaster, "POST", QStringLiteral("/auth/web3/start"),
         {{QStringLiteral("provider"), QStringLiteral("farcaster")},
          {QStringLiteral("fid"), fid.trimmed()},
          {QStringLiteral("address"), address.trimmed()}});
}

void IdentityClient::completeFarcaster(const QString &signature)
{
    if (m_farcasterMessage.isEmpty()) {
        setResult(false, message("ابتدا چالش Farcaster را صادر کنید.", "Issue the Farcaster challenge first."));
        return;
    }
    if (signature.trimmed().isEmpty()) {
        setResult(false, message("امضای SIWF الزامی است.", "The SIWF signature is required."));
        return;
    }
    send(m_farcasterConnectionMode ? Operation::CompleteFarcasterConnection
                                   : Operation::CompleteFarcaster,
         "POST", m_farcasterConnectionMode
             ? QStringLiteral("/account/connections/web3/complete")
             : QStringLiteral("/auth/web3/complete"),
         {{QStringLiteral("message"), m_farcasterMessage},
          {QStringLiteral("signature"), signature.trimmed()}});
}

void IdentityClient::signInWithFarcaster()
{
    if (!m_realAuthMode) {
        setResult(false, message("برای حساب واقعی، launcher را با OPENPROOF_DEMO_REAL_AUTH=1 اجرا کنید.",
                                 "Run the launcher with OPENPROOF_DEMO_REAL_AUTH=1 for a real account."));
        return;
    }
    if (m_externalAuthActive || m_busy) {
        setResult(false, message("یک ورود دیگر در حال اجراست.", "Another sign-in is already active."));
        return;
    }
    resetFarcaster();
    m_farcasterConnectionMode = false;
    setExternalAuthActive(true);
    send(Operation::BeginFarcasterRelay, "POST", QStringLiteral("/auth/web3/start"),
         {{QStringLiteral("provider"), QStringLiteral("farcaster")}});
}

void IdentityClient::connectFarcaster()
{
    if (!m_authenticated) {
        setResult(false, message("ابتدا با یکی از روش‌های موجود وارد شوید.",
                                 "Sign in with an existing method first."));
        return;
    }
    if (!m_realAuthMode) {
        setResult(false, message("اتصال حساب واقعی فقط در حالت real-auth فعال است.",
                                 "Real account connection requires real-auth mode."));
        return;
    }
    if (m_externalAuthActive || m_busy) {
        setResult(false, message("یک اتصال دیگر در حال اجراست.",
                                 "Another connection is already active."));
        return;
    }
    resetFarcaster();
    m_farcasterConnectionMode = true;
    setExternalAuthActive(true);
    send(Operation::BeginFarcasterRelay, "POST",
         QStringLiteral("/account/connections/web3/start"),
         {{QStringLiteral("provider"), QStringLiteral("farcaster")}});
}

void IdentityClient::connectRedirectProvider(const QString &provider)
{
    const QString normalized = provider.trimmed();
    if (!m_authenticated) {
        setResult(false, message("ابتدا با یکی از روش‌های موجود وارد شوید.",
                                 "Sign in with an existing method first."));
        return;
    }
    if (!m_redirectProviders.contains(normalized)) {
        setResult(false, message("این provider روی سرور فعال نیست.",
                                 "This provider is not enabled on the server."));
        return;
    }
    if (m_externalAuthActive || m_busy) {
        setResult(false, message("یک ورود یا اتصال دیگر در حال اجراست.",
                                 "Another sign-in or connection is already active."));
        return;
    }
    m_pendingConnectionProvider = normalized;
    send(Operation::IssueConnectionHandoff, "POST",
         QStringLiteral("/account/connections/handoff"),
         {{QStringLiteral("provider"), normalized},
          {QStringLiteral("return_to"), QStringLiteral("/account/connections/complete")}});
}

void IdentityClient::loadConnections()
{
    send(Operation::LoadConnections, "GET", QStringLiteral("/account/connections"));
}

void IdentityClient::disconnectConnection(const QString &provider, const QString &subject)
{
    if (provider.trimmed().isEmpty() || subject.trimmed().isEmpty()) {
        setResult(false, message("provider و subject اتصال الزامی‌اند.",
                                 "Connection provider and subject are required."));
        return;
    }
    send(Operation::DisconnectConnection, "POST",
         QStringLiteral("/account/connections/disconnect"),
         {{QStringLiteral("provider"), provider.trimmed()},
          {QStringLiteral("subject"), subject.trimmed()}});
}

void IdentityClient::createFarcasterRelayChannel(const QJsonObject &challenge)
{
    const QUrl relayBase(m_farcasterRelayUrl);
    if (!relayBase.isValid() || relayBase.scheme() != QStringLiteral("https") || relayBase.host().isEmpty()) {
        cancelExternalAuth();
        setResult(false, message("آدرس Relay باید HTTPS معتبر باشد.", "The relay URL must be valid HTTPS."));
        return;
    }
    m_farcasterNonce = challenge.value(QStringLiteral("nonce")).toString();
    m_farcasterExpiresAt = challenge.value(QStringLiteral("expires_at")).toString();
    const QString domain = challenge.value(QStringLiteral("domain")).toString();
    const QString uri = challenge.value(QStringLiteral("uri")).toString();
    if (m_farcasterNonce.isEmpty() || domain.isEmpty() || uri.isEmpty()) {
        cancelExternalAuth();
        setResult(false, message("چالش Relay ناقص بود.", "The relay challenge was incomplete."));
        return;
    }
    emit farcasterChanged();

    QUrl url = relayBase;
    url.setPath(url.path() + QStringLiteral("/channel"));
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    const QJsonObject payload{{QStringLiteral("siweUri"), uri},
                              {QStringLiteral("domain"), domain},
                              {QStringLiteral("nonce"), m_farcasterNonce},
                              {QStringLiteral("expirationTime"), m_farcasterExpiresAt}};
    setBusy(true);
    setResult(false, message("در حال ساخت کانال امن Farcaster…", "Creating a secure Farcaster channel…"));
    auto *reply = m_relayNetwork.post(request, QJsonDocument(payload).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [this, reply] {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        const QString networkError = reply->error() == QNetworkReply::NoError ? QString{} : reply->errorString();
        reply->deleteLater();
        setBusy(false);
        if (status < 200 || status >= 300 || !networkError.isEmpty()) {
            cancelExternalAuth();
            const QString detail = !apiErrorMessage(body).isEmpty() ? apiErrorMessage(body)
                : (!networkError.isEmpty() ? networkError : message("Relay پاسخ ناموفق داد.", "The relay returned an error."));
            setResult(false, message("خطای Relay (%1): %2", "Relay error (%1): %2").arg(status).arg(detail));
            return;
        }
        const QJsonObject object = QJsonDocument::fromJson(body).object();
        m_farcasterChannelToken = object.value(QStringLiteral("channelToken")).toString();
        m_farcasterConnectUrl = object.value(QStringLiteral("url")).toString();
        const QUrl connectUrl(m_farcasterConnectUrl);
        if (m_farcasterChannelToken.isEmpty() || !connectUrl.isValid()
            || connectUrl.scheme() != QStringLiteral("https")) {
            cancelExternalAuth();
            setResult(false, message("پاسخ Relay معتبر نبود.", "The relay response was invalid."));
            return;
        }
        emit farcasterChanged();
        setResult(true, message("صفحهٔ تأیید Farcaster باز شد؛ درخواست را در کیف پول تأیید کنید.",
                                "Farcaster approval opened; approve the request in your wallet."));
        QDesktopServices::openUrl(connectUrl);
        m_farcasterPollCount = 0;
        m_farcasterPollTimer.start();
    });
}

void IdentityClient::pollFarcasterRelay()
{
    if (!m_externalAuthActive || m_farcasterChannelToken.isEmpty()) return;
    if (++m_farcasterPollCount > 240) {
        cancelExternalAuth();
        setResult(false, message("مهلت تأیید Farcaster تمام شد؛ دوباره تلاش کنید.",
                                 "Farcaster approval timed out; try again."));
        return;
    }
    QUrl url(m_farcasterRelayUrl);
    url.setPath(url.path() + QStringLiteral("/channel/status"));
    QNetworkRequest request(url);
    request.setRawHeader("Authorization", QByteArray("Bearer ") + m_farcasterChannelToken.toUtf8());
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    auto *reply = m_relayNetwork.get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply] {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray body = reply->readAll();
        const QString networkError = reply->error() == QNetworkReply::NoError ? QString{} : reply->errorString();
        reply->deleteLater();
        finishFarcasterRelay(status, body, networkError);
    });
}

void IdentityClient::finishFarcasterRelay(int statusCode, const QByteArray &body,
                                          const QString &networkError)
{
    if (!m_externalAuthActive) return;
    if (statusCode < 200 || statusCode >= 300 || !networkError.isEmpty()) {
        cancelExternalAuth();
        setResult(false, message("ارتباط با Relay قطع شد؛ دوباره تلاش کنید.",
                                 "The relay connection failed; try again."));
        return;
    }
    const QJsonObject object = QJsonDocument::fromJson(body).object();
    const QString state = object.value(QStringLiteral("state")).toString();
    if (state == QStringLiteral("pending")) {
        m_farcasterPollTimer.start();
        return;
    }
    const QString nonce = object.value(QStringLiteral("nonce")).toString();
    const QString signedMessage = object.value(QStringLiteral("message")).toString();
    const QString signature = object.value(QStringLiteral("signature")).toString();
    m_farcasterFid = QString::number(object.value(QStringLiteral("fid")).toVariant().toULongLong());
    m_farcasterUsername = object.value(QStringLiteral("username")).toString();
    m_farcasterDisplayName = object.value(QStringLiteral("displayName")).toString();
    m_farcasterPfpUrl = object.value(QStringLiteral("pfpUrl")).toString();
    if (state != QStringLiteral("completed") || nonce != m_farcasterNonce
        || signedMessage.isEmpty() || signedMessage.size() > 8192
        || signature.isEmpty() || signature.size() > 8192 || m_farcasterFid == QStringLiteral("0")) {
        cancelExternalAuth();
        setResult(false, message("پاسخ امضاشدهٔ Relay معتبر نبود.", "The signed relay response was invalid."));
        return;
    }
    m_farcasterPollTimer.stop();
    m_farcasterChannelToken.clear();
    m_farcasterMessage = signedMessage;
    emit farcasterChanged();
    setResult(true, message("امضا دریافت شد؛ OpenProof در حال بررسی رجیستری اصلی است…",
                            "Signature received; OpenProof is checking the live registry…"));
    completeFarcaster(signature);
}

void IdentityClient::signInWithGoogle()
{
    signInWithRedirectProvider(QStringLiteral("google"));
}

void IdentityClient::signInWithRedirectProvider(const QString &provider)
{
    const QString normalized = provider.trimmed().toLower();
    if (!m_redirectProviders.contains(normalized)) {
        setResult(false, message("این provider روی OpenProof پیکربندی نشده است.",
                                 "This provider is not configured on OpenProof."));
        return;
    }
    if (m_oauthClientId.isEmpty()) {
        setResult(false, message("OAuth client این اپ ثبت نشده است.", "This app has no registered OAuth client."));
        return;
    }
    if (m_externalAuthActive || m_busy) {
        setResult(false, message("یک ورود دیگر در حال اجراست.", "Another sign-in is already active."));
        return;
    }
    closeOAuthListener();
    if (!m_oauthListener.listen(QHostAddress::LocalHost, 0)) {
        setResult(false, message("ساخت callback محلی ممکن نشد.", "Could not open the local callback listener."));
        return;
    }
    m_oauthRedirectUri = QStringLiteral("http://127.0.0.1:%1/oauth/callback")
        .arg(m_oauthListener.serverPort());
    m_oauthVerifier = randomBase64Url(48);
    m_oauthState = randomBase64Url(24);
    m_oauthNonce = randomBase64Url(24);
    const QByteArray digest = QCryptographicHash::hash(m_oauthVerifier.toUtf8(), QCryptographicHash::Sha256);
    const QString challenge = QString::fromLatin1(digest.toBase64(QByteArray::Base64UrlEncoding
                                                                   | QByteArray::OmitTrailingEquals));
    QUrlQuery authorizeQuery;
    authorizeQuery.addQueryItem(QStringLiteral("response_type"), QStringLiteral("code"));
    authorizeQuery.addQueryItem(QStringLiteral("client_id"), m_oauthClientId);
    authorizeQuery.addQueryItem(QStringLiteral("redirect_uri"), m_oauthRedirectUri);
    authorizeQuery.addQueryItem(QStringLiteral("scope"),
                                QStringLiteral("openid profile offline_access account"));
    authorizeQuery.addQueryItem(QStringLiteral("code_challenge"), challenge);
    authorizeQuery.addQueryItem(QStringLiteral("code_challenge_method"), QStringLiteral("S256"));
    authorizeQuery.addQueryItem(QStringLiteral("state"), m_oauthState);
    authorizeQuery.addQueryItem(QStringLiteral("nonce"), m_oauthNonce);
    const QString returnTo = QStringLiteral("/oauth/authorize?")
        + authorizeQuery.toString(QUrl::FullyEncoded);

    QUrl startUrl(m_baseUrl);
    startUrl.setPath(QStringLiteral("/auth/federated/start"));
    QUrlQuery startQuery;
    startQuery.addQueryItem(QStringLiteral("provider"), normalized);
    startQuery.addQueryItem(QStringLiteral("return_to"), returnTo);
    startUrl.setQuery(startQuery);
    m_pendingRedirectProvider = normalized;
    setExternalAuthActive(true);
    setResult(true, message("مرورگر باز شد؛ حساب %1 را تأیید و سپس رضایت OpenProof را بررسی کنید.",
                            "Browser opened; approve your %1 account and then OpenProof consent.")
                        .arg(normalized));
    if (!QDesktopServices::openUrl(startUrl)) {
        cancelExternalAuth();
        setResult(false, message("بازکردن مرورگر ممکن نشد.", "Could not open the system browser."));
    }
}

void IdentityClient::acceptOAuthCallback()
{
    while (m_oauthListener.hasPendingConnections()) {
        QTcpSocket *socket = m_oauthListener.nextPendingConnection();
        QPointer<QTcpSocket> guard(socket);
        const auto process = [this, guard] {
            if (!guard) return;
            if (guard->bytesAvailable() > 16384) {
                guard->disconnectFromHost();
                cancelExternalAuth();
                setResult(false, message("callback محلی بیش از حد بزرگ بود.", "The local callback was too large."));
                return;
            }
            const QByteArray request = guard->peek(16384);
            if (!request.contains("\r\n\r\n")) return;
            if (guard->property("openproofOAuthCallbackHandled").toBool()) return;
            guard->setProperty("openproofOAuthCallbackHandled", true);
            const QList<QByteArray> firstLine = request.left(request.indexOf("\r\n")).split(' ');
            guard->readAll();
            QString code;
            QString error;
            bool valid = firstLine.size() == 3 && firstLine[0] == "GET";
            if (valid) {
                const QUrl target(QString::fromLatin1(firstLine[1]));
                const QUrlQuery query(target);
                valid = target.path() == QStringLiteral("/oauth/callback")
                    && query.queryItemValue(QStringLiteral("state")) == m_oauthState
                    && query.queryItemValue(QStringLiteral("iss")) == m_baseUrl;
                code = query.queryItemValue(QStringLiteral("code"));
                error = query.queryItemValue(QStringLiteral("error"));
                valid = valid && error.isEmpty() && !code.isEmpty();
            }
            const QByteArray html = valid
                ? QByteArray("<!doctype html><meta charset=utf-8><title>OpenProof</title><h1>Sign-in complete</h1><p>You can return to the OpenProof app.</p>")
                : QByteArray("<!doctype html><meta charset=utf-8><title>OpenProof</title><h1>Sign-in failed</h1><p>Return to the app and try again.</p>");
            const QByteArray response = QByteArray("HTTP/1.1 ") + (valid ? "200 OK\r\n" : "400 Bad Request\r\n")
                + "Content-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n"
                + "Content-Security-Policy: default-src 'none'\r\nContent-Length: "
                + QByteArray::number(html.size()) + "\r\n\r\n" + html;
            guard->write(response);
            guard->disconnectFromHost();
            closeOAuthListener();
            if (!valid) {
                cancelExternalAuth();
                setResult(false, error.isEmpty()
                    ? message("callback OAuth معتبر نبود.", "The OAuth callback was invalid.")
                    : message("ورود provider لغو یا رد شد: %1",
                              "Provider sign-in was cancelled or denied: %1").arg(error));
                return;
            }
            exchangeAuthorizationCode(code);
        };
        connect(socket, &QTcpSocket::readyRead, this, process);
        // The browser can send the complete GET between nextPendingConnection()
        // and the readyRead connection above. In that case Qt has already
        // emitted the edge-triggered signal, so process the buffered request now.
        if (socket->bytesAvailable() > 0) process();
    }
}

void IdentityClient::exchangeAuthorizationCode(const QString &code)
{
    QUrlQuery form;
    form.addQueryItem(QStringLiteral("grant_type"), QStringLiteral("authorization_code"));
    form.addQueryItem(QStringLiteral("client_id"), m_oauthClientId);
    form.addQueryItem(QStringLiteral("code"), code);
    form.addQueryItem(QStringLiteral("redirect_uri"), m_oauthRedirectUri);
    form.addQueryItem(QStringLiteral("code_verifier"), m_oauthVerifier);
    sendForm(Operation::OAuthToken, QStringLiteral("/oauth/token"),
             form.toString(QUrl::FullyEncoded).toUtf8());
}

void IdentityClient::closeOAuthListener()
{
    if (m_oauthListener.isListening()) m_oauthListener.close();
}

void IdentityClient::cancelExternalAuth()
{
    m_farcasterPollTimer.stop();
    m_connectionPollTimer.stop();
    m_farcasterChannelToken.clear();
    closeOAuthListener();
    m_oauthState.clear();
    m_oauthNonce.clear();
    m_oauthVerifier.clear();
    m_oauthRedirectUri.clear();
    m_pendingRedirectProvider.clear();
    m_pendingConnectionProvider.clear();
    m_connectionPollCount = 0;
    m_farcasterConnectionMode = false;
    setExternalAuthActive(false);
}

void IdentityClient::resetFarcaster()
{
    m_farcasterPollTimer.stop();
    const bool changed = !m_farcasterMessage.isEmpty() || !m_farcasterNonce.isEmpty()
        || !m_farcasterSignerKind.isEmpty() || !m_farcasterExpiresAt.isEmpty()
        || !m_farcasterConnectUrl.isEmpty() || !m_farcasterFid.isEmpty()
        || !m_farcasterUsername.isEmpty() || !m_farcasterDisplayName.isEmpty()
        || !m_farcasterPfpUrl.isEmpty();
    m_farcasterMessage.clear();
    m_farcasterNonce.clear();
    m_farcasterSignerKind.clear();
    m_farcasterExpiresAt.clear();
    m_farcasterConnectUrl.clear();
    m_farcasterFid.clear();
    m_farcasterUsername.clear();
    m_farcasterDisplayName.clear();
    m_farcasterPfpUrl.clear();
    m_farcasterChannelToken.clear();
    if (changed) emit farcasterChanged();
}

void IdentityClient::loadProfile() { send(Operation::LoadProfile, "GET", QStringLiteral("/account/profile")); }

void IdentityClient::updateProfile(const QString &displayName, const QString &locale)
{
    QJsonObject body;
    if (!displayName.trimmed().isEmpty()) body.insert(QStringLiteral("display_name"), displayName.trimmed());
    if (!locale.trimmed().isEmpty()) body.insert(QStringLiteral("locale"), locale.trimmed());
    if (body.isEmpty()) {
        setResult(false, message("حداقل یک مقدار پروفایل وارد کنید.", "Enter at least one profile value."));
        return;
    }
    send(Operation::UpdateProfile, "PATCH", QStringLiteral("/account/profile"), body);
}

void IdentityClient::clearOAuthTokens()
{
    m_accessToken.clear();
    m_refreshToken.clear();
    setAuthenticationMethod({});
}

void IdentityClient::applyProfile(const QJsonObject &profile)
{
    m_profileIdentityId = profile.value(QStringLiteral("identity_id")).toString();
    if (m_profileIdentityId.isEmpty()) m_profileIdentityId = profile.value(QStringLiteral("sub")).toString();
    m_profileDisplayName = profile.value(QStringLiteral("display_name")).toString();
    if (m_profileDisplayName.isEmpty()) m_profileDisplayName = profile.value(QStringLiteral("name")).toString();
    m_profileEmail = profile.value(QStringLiteral("email")).toString();
    m_profileLocale = profile.value(QStringLiteral("locale")).toString();
    m_profilePicture = profile.value(QStringLiteral("picture")).toString();
    m_profileEmailVerified = profile.value(QStringLiteral("email_verified")).toBool(false);
    emit profileChanged();
}

void IdentityClient::logout()
{
    cancelExternalAuth();
    if (!m_accessToken.isEmpty()) {
        QUrlQuery form;
        form.addQueryItem(QStringLiteral("token"), m_accessToken);
        form.addQueryItem(QStringLiteral("client_id"), m_oauthClientId);
        sendForm(Operation::RevokeToken, QStringLiteral("/oauth/revoke"),
                 form.toString(QUrl::FullyEncoded).toUtf8());
        return;
    }
    send(Operation::Logout, "POST", QStringLiteral("/auth/logout"));
}

void IdentityClient::send(Operation operation, const QByteArray &method, const QString &path,
                          const QJsonObject &body)
{
    if (m_busy) {
        setResult(false, message("یک درخواست دیگر هنوز در حال اجراست.", "Another request is still running."));
        return;
    }
    const QUrl base(m_baseUrl);
    if (!base.isValid() || (base.scheme() != QStringLiteral("https") && base.scheme() != QStringLiteral("http"))
        || base.host().isEmpty()) {
        setResult(false, message("آدرس OpenProof معتبر نیست.", "The OpenProof URL is invalid."));
        return;
    }
    if (base.scheme() == QStringLiteral("http") && !isLoopbackHost(base.host())) {
        setResult(false, message("HTTP فقط برای localhost مجاز است؛ برای شبکه از HTTPS استفاده کنید.",
                                 "HTTP is allowed only on localhost; use HTTPS on a network."));
        return;
    }
    QUrl url = base;
    url.setPath(path);
    url.setQuery(QString{});
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    if (!m_accessToken.isEmpty() && (path.startsWith(QStringLiteral("/account/"))
                                     || path == QStringLiteral("/oauth/userinfo"))) {
        request.setRawHeader("Authorization", QByteArray("Bearer ") + m_accessToken.toUtf8());
    }
    QString sslError;
    if (!configureSsl(request, m_caCertificatePath, &sslError)) {
        setResult(false, m_english ? sslError : message("فایل CA محلی معتبر نیست.", "The local CA file is invalid."));
        return;
    }
    setBusy(true);
    setResult(false, message("در حال ارسال درخواست…", "Sending request…"));
    const QByteArray payload = body.isEmpty() ? QByteArray{} : QJsonDocument(body).toJson(QJsonDocument::Compact);
    QNetworkReply *reply = method == "GET" ? m_network.get(request)
        : (method == "POST" ? m_network.post(request, payload)
                            : m_network.sendCustomRequest(request, method, payload));
    connect(reply, &QNetworkReply::finished, this, [this, reply, operation] {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray responseBody = reply->readAll();
        const QString networkError = reply->error() == QNetworkReply::NoError ? QString{} : reply->errorString();
        reply->deleteLater();
        setBusy(false);
        finish(operation, status, responseBody, networkError);
    });
}

void IdentityClient::sendForm(Operation operation, const QString &path, const QByteArray &body)
{
    if (m_busy) {
        setResult(false, message("یک درخواست دیگر هنوز در حال اجراست.", "Another request is still running."));
        return;
    }
    QUrl url(m_baseUrl);
    url.setPath(path);
    url.setQuery(QString{});
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    QString sslError;
    if (!configureSsl(request, m_caCertificatePath, &sslError)) {
        setResult(false, m_english ? sslError : message("فایل CA محلی معتبر نیست.", "The local CA file is invalid."));
        return;
    }
    setBusy(true);
    setResult(false, operation == Operation::OAuthToken
        ? message("در حال تبادل امن authorization code…", "Securely exchanging the authorization code…")
        : message("در حال باطل‌کردن token…", "Revoking token…"));
    auto *reply = m_network.post(request, body);
    connect(reply, &QNetworkReply::finished, this, [this, reply, operation] {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray responseBody = reply->readAll();
        const QString networkError = reply->error() == QNetworkReply::NoError ? QString{} : reply->errorString();
        reply->deleteLater();
        setBusy(false);
        finish(operation, status, responseBody, networkError);
    });
}

void IdentityClient::finish(Operation operation, int statusCode, const QByteArray &body,
                            const QString &networkError)
{
    const bool success = statusCode >= 200 && statusCode < 300 && networkError.isEmpty();
    const QString rendered = prettyBody(body, m_english);
    if (!success) {
        if (operation == Operation::OAuthToken
            || operation == Operation::IssueConnectionHandoff) {
            cancelExternalAuth();
        } else if (operation == Operation::LoadConnections
                   && m_externalAuthActive && !m_pendingConnectionProvider.isEmpty()) {
            m_connectionPollTimer.start();
        }
        const QString detail = !apiErrorMessage(body).isEmpty() ? apiErrorMessage(body)
            : (!networkError.isEmpty() ? networkError : message("پاسخ ناموفق", "Unsuccessful response"));
        setResult(false, message("خطا (%1): %2", "Error (%1): %2").arg(statusCode).arg(detail),
                  operation == Operation::OAuthToken ? QString{} : rendered);
        return;
    }

    const QJsonObject object = QJsonDocument::fromJson(body).object();
    switch (operation) {
    case Operation::Health:
        setResult(true, message("OpenProof آماده است.", "OpenProof is ready."), rendered);
        break;
    case Operation::Providers: {
        QStringList providers;
        for (const auto &provider : object.value(QStringLiteral("providers")).toArray()) {
            const QString value = provider.toString();
            if (!value.isEmpty() && !providers.contains(value)) providers.push_back(value);
        }
        providers.sort(Qt::CaseInsensitive);
        const bool available = providers.contains(QStringLiteral("google"));
        const bool providerSetChanged = providers != m_redirectProviders;
        const bool googleChanged = m_googleAvailable != available;
        m_redirectProviders = std::move(providers);
        m_googleAvailable = available;
        if (providerSetChanged || googleChanged) emit providersChanged();
        setResult(true, m_redirectProviders.isEmpty()
            ? message("هیچ redirect providerی روی این سرور فعال نیست.",
                      "No redirect provider is enabled on this server.")
            : message("%1 ارائه‌دهندهٔ ورود روی این سرور فعال است.",
                      "%1 sign-in provider(s) are enabled on this server.")
                  .arg(m_redirectProviders.size()), rendered);
        break;
    }
    case Operation::Signup:
        setResult(true, message("حساب ساخته شد؛ حالا ایمیل را تأیید کنید.", "Account created; verify the email next."), rendered);
        break;
    case Operation::VerifyEmail:
        setResult(true, message("ایمیل تأیید شد؛ می‌توانید وارد شوید.", "Email verified; you can now sign in."), rendered);
        break;
    case Operation::BeginLogin:
        m_transactionId = object.value(QStringLiteral("transaction_id")).toString();
        m_challengeId = object.value(QStringLiteral("challenge_id")).toString();
        emit transactionChanged();
        setResult(!m_transactionId.isEmpty() && !m_challengeId.isEmpty(),
                  message("چالش ورود دریافت شد؛ رمز/MFA را ارسال کنید.", "Login challenge received; submit password/MFA."), rendered);
        break;
    case Operation::CompleteLogin:
        setAuthenticationMethod(QStringLiteral("local"));
        setAuthenticated(true);
        setResult(true, message("ورود موفق؛ session cookie داخل اپ نگهداری شد.", "Signed in; the session cookie is held inside the app."), rendered);
        break;
    case Operation::BeginFarcaster:
        m_farcasterMessage = object.value(QStringLiteral("message")).toString();
        m_farcasterNonce = object.value(QStringLiteral("nonce")).toString();
        m_farcasterSignerKind = object.value(QStringLiteral("signer_kind")).toString();
        m_farcasterExpiresAt = object.value(QStringLiteral("expires_at")).toString();
        emit farcasterChanged();
        setResult(!m_farcasterMessage.isEmpty() && !m_farcasterNonce.isEmpty(),
                  message("پیام استاندارد SIWF صادر شد؛ آن را دقیق امضا کنید.",
                          "Standard SIWF message issued; sign it exactly."), rendered);
        break;
    case Operation::BeginFarcasterRelay:
        createFarcasterRelayChannel(object);
        break;
    case Operation::CompleteFarcaster:
        setExternalAuthActive(false);
        setAuthenticationMethod(QStringLiteral("farcaster"));
        setAuthenticated(true);
        setResult(true, message("FID در رجیستری اصلی تأیید شد و session امن صادر شد.",
                                "FID verified against the live registry and a secure session was issued."), rendered);
        break;
    case Operation::CompleteFarcasterConnection:
        cancelExternalAuth();
        m_pendingConnectionProvider = QStringLiteral("farcaster");
        loadConnections();
        break;
    case Operation::LoadProfile:
        applyProfile(object);
        setAuthenticated(true);
        setResult(true, message("پروفایل canonical دریافت شد.", "Canonical profile loaded."), rendered);
        break;
    case Operation::UpdateProfile:
        applyProfile(object);
        setResult(true, message("پروفایل به‌روزرسانی شد.", "Profile updated."), rendered);
        break;
    case Operation::LoadConnections: {
        QVariantList connections;
        for (const auto &value : object.value(QStringLiteral("connections")).toArray()) {
            if (!value.isObject()) continue;
            const auto connection = value.toObject();
            QVariantMap item;
            item.insert(QStringLiteral("provider"),
                        connection.value(QStringLiteral("provider")).toString());
            item.insert(QStringLiteral("subject"),
                        connection.value(QStringLiteral("subject")).toString());
            connections.push_back(item);
        }
        m_connections = std::move(connections);
        emit connectionsChanged();
        const QString completedProvider = m_pendingConnectionProvider;
        const bool connectionCompleted = !completedProvider.isEmpty()
            && std::any_of(m_connections.cbegin(), m_connections.cend(),
                           [&completedProvider](const QVariant &value) {
                return value.toMap().value(QStringLiteral("provider")).toString()
                    == completedProvider;
            });
        if (connectionCompleted) {
            cancelExternalAuth();
            setResult(true, message("provider %1 به همان هویت canonical متصل شد.",
                                    "%1 connected to the same canonical identity.")
                                .arg(completedProvider), rendered);
        } else if (m_externalAuthActive && !m_pendingConnectionProvider.isEmpty()) {
            setResult(true, message("منتظر تأیید provider در مرورگر هستیم…",
                                    "Waiting for provider approval in the browser…"), rendered);
            m_connectionPollTimer.start();
        } else {
            setResult(true, message("روش‌های ورود متصل دریافت شدند.",
                                    "Connected sign-in methods loaded."), rendered);
        }
        break;
    }
    case Operation::DisconnectConnection:
        setResult(true, message("روش ورود جدا شد؛ حداقل یک روش امن باقی مانده است.",
                                "Sign-in method disconnected; at least one safe method remains."), rendered);
        loadConnections();
        break;
    case Operation::IssueConnectionHandoff: {
        const QString localPath = object.value(QStringLiteral("handoff_url")).toString();
        QUrl handoff(m_baseUrl);
        const QUrl relative(localPath);
        if (localPath.isEmpty() || !relative.isRelative() || !localPath.startsWith('/')) {
            cancelExternalAuth();
            setResult(false, message("پاسخ handoff معتبر نبود.",
                                     "The handoff response was invalid."));
            break;
        }
        handoff.setPath(relative.path());
        handoff.setQuery(relative.query());
        setExternalAuthActive(true);
        m_connectionPollCount = 0;
        setResult(true, message("مرورگر باز شد؛ بعد از تأیید، فهرست خودکار به‌روز می‌شود.",
                                "Browser opened; the list will refresh automatically after approval."));
        if (!QDesktopServices::openUrl(handoff)) {
            cancelExternalAuth();
            setResult(false, message("بازکردن مرورگر ممکن نشد.",
                                     "Could not open the system browser."));
        } else {
            m_connectionPollTimer.start();
        }
        break;
    }
    case Operation::Logout:
        applyProfile({});
        setAuthenticationMethod({});
        setAuthenticated(false);
        setResult(true, message("خروج انجام شد و session باطل شد.", "Signed out and the session was revoked."), rendered);
        break;
    case Operation::OAuthToken:
        m_accessToken = object.value(QStringLiteral("access_token")).toString();
        m_refreshToken = object.value(QStringLiteral("refresh_token")).toString();
        {
        const QString provider = m_pendingRedirectProvider.isEmpty()
            ? QStringLiteral("federated") : m_pendingRedirectProvider;
        cancelExternalAuth();
        if (m_accessToken.isEmpty()) {
            setResult(false, message("پاسخ token معتبر نبود.", "The token response was invalid."));
            break;
        }
        setAuthenticationMethod(provider);
        setAuthenticated(true);
        setResult(true, message("ورود %1 کامل شد؛ در حال دریافت پروفایل canonical…",
                                "%1 sign-in complete; loading the canonical profile…")
                            .arg(provider));
        }
        break;
    case Operation::RevokeToken:
        applyProfile({});
        clearOAuthTokens();
        setAuthenticated(false);
        setResult(true, message("Access token باطل و از حافظه پاک شد.", "Access token revoked and cleared from memory."));
        break;
    }
}
