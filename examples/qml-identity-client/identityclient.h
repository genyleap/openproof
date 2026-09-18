#pragma once

#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTcpServer>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class IdentityClient : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(QString baseUrl READ baseUrl WRITE setBaseUrl NOTIFY baseUrlChanged)
    Q_PROPERTY(QString caCertificatePath READ caCertificatePath WRITE setCaCertificatePath NOTIFY caCertificatePathChanged)
    Q_PROPERTY(QString oauthClientId READ oauthClientId WRITE setOauthClientId NOTIFY oauthConfigurationChanged)
    Q_PROPERTY(QString farcasterRelayUrl READ farcasterRelayUrl WRITE setFarcasterRelayUrl NOTIFY farcasterConfigurationChanged)
    Q_PROPERTY(bool realAuthMode READ realAuthMode WRITE setRealAuthMode NOTIFY realAuthModeChanged)
    Q_PROPERTY(bool googleAvailable READ googleAvailable NOTIFY providersChanged)
    Q_PROPERTY(QStringList redirectProviders READ redirectProviders NOTIFY providersChanged)
    Q_PROPERTY(QVariantList connections READ connections NOTIFY connectionsChanged)
    Q_PROPERTY(bool externalAuthActive READ externalAuthActive NOTIFY externalAuthChanged)
    Q_PROPERTY(QString authenticationMethod READ authenticationMethod NOTIFY authenticationMethodChanged)
    Q_PROPERTY(QString profileIdentityId READ profileIdentityId NOTIFY profileChanged)
    Q_PROPERTY(QString profileDisplayName READ profileDisplayName NOTIFY profileChanged)
    Q_PROPERTY(QString profileEmail READ profileEmail NOTIFY profileChanged)
    Q_PROPERTY(QString profileLocale READ profileLocale NOTIFY profileChanged)
    Q_PROPERTY(QString profilePicture READ profilePicture NOTIFY profileChanged)
    Q_PROPERTY(bool profileEmailVerified READ profileEmailVerified NOTIFY profileChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(bool authenticated READ authenticated NOTIFY authenticatedChanged)
    Q_PROPERTY(bool lastRequestSucceeded READ lastRequestSucceeded NOTIFY lastRequestSucceededChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(QString responseText READ responseText NOTIFY responseTextChanged)
    Q_PROPERTY(QString transactionId READ transactionId NOTIFY transactionChanged)
    Q_PROPERTY(QString challengeId READ challengeId NOTIFY transactionChanged)
    Q_PROPERTY(QString farcasterMessage READ farcasterMessage NOTIFY farcasterChanged)
    Q_PROPERTY(QString farcasterNonce READ farcasterNonce NOTIFY farcasterChanged)
    Q_PROPERTY(QString farcasterSignerKind READ farcasterSignerKind NOTIFY farcasterChanged)
    Q_PROPERTY(QString farcasterExpiresAt READ farcasterExpiresAt NOTIFY farcasterChanged)
    Q_PROPERTY(QString farcasterConnectUrl READ farcasterConnectUrl NOTIFY farcasterChanged)
    Q_PROPERTY(QString farcasterFid READ farcasterFid NOTIFY farcasterChanged)
    Q_PROPERTY(QString farcasterUsername READ farcasterUsername NOTIFY farcasterChanged)
    Q_PROPERTY(QString farcasterDisplayName READ farcasterDisplayName NOTIFY farcasterChanged)
    Q_PROPERTY(QString farcasterPfpUrl READ farcasterPfpUrl NOTIFY farcasterChanged)
    Q_PROPERTY(bool farcasterChallengeReady READ farcasterChallengeReady NOTIFY farcasterChanged)
    Q_PROPERTY(bool english READ english WRITE setEnglish NOTIFY languageChanged)

public:
    explicit IdentityClient(QObject *parent = nullptr);

    [[nodiscard]] QString baseUrl() const;
    void setBaseUrl(const QString &value);
    [[nodiscard]] QString caCertificatePath() const;
    void setCaCertificatePath(const QString &value);
    [[nodiscard]] QString oauthClientId() const;
    void setOauthClientId(const QString &value);
    [[nodiscard]] QString farcasterRelayUrl() const;
    void setFarcasterRelayUrl(const QString &value);
    [[nodiscard]] bool realAuthMode() const;
    void setRealAuthMode(bool value);
    [[nodiscard]] bool googleAvailable() const;
    [[nodiscard]] QStringList redirectProviders() const;
    [[nodiscard]] QVariantList connections() const;
    [[nodiscard]] bool externalAuthActive() const;
    [[nodiscard]] QString authenticationMethod() const;
    [[nodiscard]] QString profileIdentityId() const;
    [[nodiscard]] QString profileDisplayName() const;
    [[nodiscard]] QString profileEmail() const;
    [[nodiscard]] QString profileLocale() const;
    [[nodiscard]] QString profilePicture() const;
    [[nodiscard]] bool profileEmailVerified() const;
    [[nodiscard]] bool busy() const;
    [[nodiscard]] bool authenticated() const;
    [[nodiscard]] bool lastRequestSucceeded() const;
    [[nodiscard]] QString statusMessage() const;
    [[nodiscard]] QString responseText() const;
    [[nodiscard]] QString transactionId() const;
    [[nodiscard]] QString challengeId() const;
    [[nodiscard]] QString farcasterMessage() const;
    [[nodiscard]] QString farcasterNonce() const;
    [[nodiscard]] QString farcasterSignerKind() const;
    [[nodiscard]] QString farcasterExpiresAt() const;
    [[nodiscard]] QString farcasterConnectUrl() const;
    [[nodiscard]] QString farcasterFid() const;
    [[nodiscard]] QString farcasterUsername() const;
    [[nodiscard]] QString farcasterDisplayName() const;
    [[nodiscard]] QString farcasterPfpUrl() const;
    [[nodiscard]] bool farcasterChallengeReady() const;
    [[nodiscard]] bool english() const;
    void setEnglish(bool value);

    Q_INVOKABLE void checkHealth();
    Q_INVOKABLE void refreshProviders();
    Q_INVOKABLE void signInWithRedirectProvider(const QString &provider);
    Q_INVOKABLE void signInWithGoogle();
    Q_INVOKABLE void signInWithFarcaster();
    Q_INVOKABLE void connectFarcaster();
    Q_INVOKABLE void connectRedirectProvider(const QString &provider);
    Q_INVOKABLE void loadConnections();
    Q_INVOKABLE void disconnectConnection(const QString &provider, const QString &subject);
    Q_INVOKABLE void cancelExternalAuth();
    Q_INVOKABLE void signup(const QString &email, const QString &password, const QString &displayName);
    Q_INVOKABLE void verifyEmail(const QString &verificationId, const QString &secret);
    Q_INVOKABLE void beginLogin(const QString &subject);
    Q_INVOKABLE void completeLogin(const QString &password, const QString &totp);
    Q_INVOKABLE void beginFarcaster(const QString &fid, const QString &address);
    Q_INVOKABLE void completeFarcaster(const QString &signature);
    Q_INVOKABLE void resetFarcaster();
    Q_INVOKABLE void loadProfile();
    Q_INVOKABLE void updateProfile(const QString &displayName, const QString &locale);
    Q_INVOKABLE void logout();
    Q_INVOKABLE void clearOutput();

signals:
    void baseUrlChanged();
    void caCertificatePathChanged();
    void oauthConfigurationChanged();
    void farcasterConfigurationChanged();
    void realAuthModeChanged();
    void providersChanged();
    void connectionsChanged();
    void externalAuthChanged();
    void authenticationMethodChanged();
    void profileChanged();
    void busyChanged();
    void authenticatedChanged();
    void lastRequestSucceededChanged();
    void statusMessageChanged();
    void responseTextChanged();
    void transactionChanged();
    void farcasterChanged();
    void languageChanged();

private:
    enum class Operation {
        Health, Providers, Signup, VerifyEmail, BeginLogin, CompleteLogin,
        BeginFarcaster, BeginFarcasterRelay, CompleteFarcaster,
        CompleteFarcasterConnection, LoadProfile, UpdateProfile,
        LoadConnections, DisconnectConnection, IssueConnectionHandoff,
        Logout, OAuthToken, RevokeToken
    };

    void send(Operation operation, const QByteArray &method, const QString &path, const QJsonObject &body = {});
    void sendForm(Operation operation, const QString &path, const QByteArray &body);
    void finish(Operation operation, int statusCode, const QByteArray &body, const QString &networkError);
    void createFarcasterRelayChannel(const QJsonObject &challenge);
    void pollFarcasterRelay();
    void finishFarcasterRelay(int statusCode, const QByteArray &body, const QString &networkError);
    void acceptOAuthCallback();
    void exchangeAuthorizationCode(const QString &code);
    void closeOAuthListener();
    void clearOAuthTokens();
    void applyProfile(const QJsonObject &profile);
    void setAuthenticationMethod(QString value);
    void setExternalAuthActive(bool value);
    void setBusy(bool value);
    void setAuthenticated(bool value);
    void setResult(bool success, QString message, QString response = {});
    [[nodiscard]] QString message(const char *persian, const char *english) const;

    QNetworkAccessManager m_network;
    QNetworkAccessManager m_relayNetwork;
    QTcpServer m_oauthListener;
    QTimer m_farcasterPollTimer;
    QTimer m_connectionPollTimer;
    QString m_baseUrl{"https://127.0.0.1:18443"};
    QString m_caCertificatePath;
    QString m_oauthClientId;
    QString m_farcasterRelayUrl{"https://relay.farcaster.xyz/v1"};
    QString m_statusMessage{"آماده اتصال به OpenProof"};
    QString m_responseText;
    QString m_transactionId;
    QString m_challengeId;
    QString m_farcasterMessage;
    QString m_farcasterNonce;
    QString m_farcasterSignerKind;
    QString m_farcasterExpiresAt;
    QString m_farcasterConnectUrl;
    QString m_farcasterFid;
    QString m_farcasterUsername;
    QString m_farcasterDisplayName;
    QString m_farcasterPfpUrl;
    QString m_farcasterChannelToken;
    QString m_oauthState;
    QString m_oauthNonce;
    QString m_oauthVerifier;
    QString m_oauthRedirectUri;
    QString m_pendingRedirectProvider;
    QString m_pendingConnectionProvider;
    QString m_accessToken;
    QString m_refreshToken;
    QString m_authenticationMethod;
    QStringList m_redirectProviders;
    QVariantList m_connections;
    QString m_profileIdentityId;
    QString m_profileDisplayName;
    QString m_profileEmail;
    QString m_profileLocale;
    QString m_profilePicture;
    int m_farcasterPollCount{};
    int m_connectionPollCount{};
    bool m_realAuthMode{};
    bool m_googleAvailable{};
    bool m_farcasterConnectionMode{};
    bool m_externalAuthActive{};
    bool m_busy{};
    bool m_authenticated{};
    bool m_lastRequestSucceeded{};
    bool m_profileEmailVerified{};
    bool m_english{};
};
