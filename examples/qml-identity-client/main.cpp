#include "identityclient.h"

#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QFile>
#include <QFont>
#include <QGuiApplication>
#include <QJsonDocument>
#include <QMap>
#include <QQmlApplicationEngine>
#include <QQuickWindow>
#include <QTimer>

#include <memory>

int main(int argc, char *argv[])
{
    qputenv("QT_QUICK_CONTROLS_STYLE", "Basic");
    QGuiApplication application(argc, argv);
#if defined(Q_OS_MACOS)
    application.setFont(QFont(QStringLiteral(".AppleSystemUIFont")));
#endif
    application.setApplicationName(QStringLiteral("OpenProof Identity Demo"));
    application.setOrganizationName(QStringLiteral("OpenProof"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("C++/QML client for the OpenProof identity API"));
    parser.addHelpOption();
    QCommandLineOption connectionOption(
        QStringList{QStringLiteral("c"), QStringLiteral("connection-file")},
        QStringLiteral("Read the disposable local demo connection JSON."),
        QStringLiteral("path"));
    QCommandLineOption smokeOption(QStringLiteral("smoke"),
                                   QStringLiteral("Load QML offscreen and exit."));
    QCommandLineOption apiSmokeOption(
        QStringLiteral("api-smoke"),
        QStringLiteral("Run health, Farcaster SIWF, login, profile, connections and logout against the supplied demo stack."));
    QCommandLineOption snapshotOption(
        QStringLiteral("snapshot"),
        QStringLiteral("Render the client and save a screenshot for visual regression checks."),
        QStringLiteral("path"));
    QCommandLineOption languageOption(
        QStringLiteral("language"),
        QStringLiteral("Initial interface language: fa or en."),
        QStringLiteral("locale"), QStringLiteral("fa"));
    QCommandLineOption pageOption(
        QStringLiteral("page"),
        QStringLiteral("Initial page: overview, farcaster, login, signup, profile, connections or connection."),
        QStringLiteral("name"), QStringLiteral("overview"));
    parser.addOption(connectionOption);
    parser.addOption(smokeOption);
    parser.addOption(apiSmokeOption);
    parser.addOption(snapshotOption);
    parser.addOption(languageOption);
    parser.addOption(pageOption);
    parser.process(application);

    QString baseUrl = QStringLiteral("https://127.0.0.1:18443");
    QString caCertificate;
    QString demoSubject;
    QString demoPassword;
    QString demoPortalUrl;
    QString oauthClientId;
    QString farcasterRelayUrl = QStringLiteral("https://relay.farcaster.xyz/v1");
    bool realAuthMode = false;
    if (parser.isSet(connectionOption)) {
        QFile file(parser.value(connectionOption));
        if (!file.open(QIODevice::ReadOnly)) return 2;
        const QJsonObject connection = QJsonDocument::fromJson(file.readAll()).object();
        baseUrl = connection.value(QStringLiteral("base_url")).toString(baseUrl);
        caCertificate = connection.value(QStringLiteral("ca_certificate")).toString();
        demoSubject = connection.value(QStringLiteral("subject")).toString();
        demoPassword = connection.value(QStringLiteral("password")).toString();
        demoPortalUrl = connection.value(QStringLiteral("portal_url")).toString();
        oauthClientId = connection.value(QStringLiteral("oauth_client_id")).toString();
        farcasterRelayUrl = connection.value(QStringLiteral("farcaster_relay_url"))
            .toString(farcasterRelayUrl);
        realAuthMode = connection.value(QStringLiteral("real_auth_mode")).toBool(false);
    }

    QQmlApplicationEngine engine;
    const QMap<QString, int> pages{{QStringLiteral("overview"), 0},
                                   {QStringLiteral("farcaster"), 1},
                                   {QStringLiteral("login"), 2},
                                   {QStringLiteral("signup"), 3},
                                   {QStringLiteral("profile"), 4},
                                   {QStringLiteral("connections"), 5},
                                   {QStringLiteral("connection"), 6},
                                   {QStringLiteral("settings"), 6}};
    const int initialPage = pages.value(parser.value(pageOption).toLower(), 0);
    engine.setInitialProperties({
        {QStringLiteral("configuredBaseUrl"), baseUrl},
        {QStringLiteral("configuredCaCertificate"), caCertificate},
        {QStringLiteral("configuredDemoSubject"), demoSubject},
        {QStringLiteral("configuredDemoPassword"), demoPassword},
        {QStringLiteral("configuredPortalUrl"), demoPortalUrl},
        {QStringLiteral("configuredOauthClientId"), oauthClientId},
        {QStringLiteral("configuredFarcasterRelayUrl"), farcasterRelayUrl},
        {QStringLiteral("configuredRealAuthMode"), realAuthMode},
        {QStringLiteral("configuredAutomaticProviderDiscovery"), !parser.isSet(apiSmokeOption)},
        {QStringLiteral("configuredLanguage"),
         parser.value(languageOption).compare(QStringLiteral("en"), Qt::CaseInsensitive) == 0
             ? QStringLiteral("en") : QStringLiteral("fa")},
        {QStringLiteral("pageIndex"), initialPage},
    });
    engine.loadFromModule("OpenProof.Demo", "Main");
    if (engine.rootObjects().isEmpty()) return 1;
    if (parser.isSet(apiSmokeOption)) {
        auto *client = engine.rootObjects().constFirst()->findChild<IdentityClient *>(
            QStringLiteral("identityClient"));
        if (client == nullptr || demoSubject.isEmpty() || demoPassword.isEmpty()) return 3;
        const auto completedStage = std::make_shared<int>(0);
        QObject::connect(client, &IdentityClient::busyChanged, &application,
                         [client, completedStage, demoSubject, demoPassword, realAuthMode, &application] {
            if (client->busy()) return;
            QTimer::singleShot(0, &application,
                               [client, completedStage, demoSubject, demoPassword, realAuthMode, &application] {
                if (!client->lastRequestSucceeded()) {
                    application.exit(4);
                    return;
                }
                if (realAuthMode) {
                    switch ((*completedStage)++) {
                    case 0: client->beginLogin(demoSubject); break;
                    case 1: client->completeLogin(demoPassword, {}); break;
                    case 2: client->loadProfile(); break;
                    case 3: client->loadConnections(); break;
                    case 4: client->logout(); break;
                    default: application.quit(); break;
                    }
                    return;
                }
                switch ((*completedStage)++) {
                case 0: client->beginFarcaster(
                    QStringLiteral("6841"),
                    QStringLiteral("0x1111111111111111111111111111111111111111")); break;
                case 1: client->completeFarcaster(QStringLiteral("0x0102")); break;
                case 2: client->logout(); break;
                case 3: client->beginLogin(demoSubject); break;
                case 4: client->completeLogin(demoPassword, {}); break;
                case 5: client->loadProfile(); break;
                case 6: client->loadConnections(); break;
                case 7: client->logout(); break;
                default: application.quit(); break;
                }
            });
        });
        QTimer::singleShot(30'000, &application, [&application] { application.exit(5); });
        client->checkHealth();
    } else if (parser.isSet(snapshotOption)) {
        auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().constFirst());
        if (window == nullptr) return 6;
        const QString snapshotPath = parser.value(snapshotOption);
        QTimer::singleShot(500, &application, [window, snapshotPath, &application] {
            application.exit(window->grabWindow().save(snapshotPath) ? 0 : 7);
        });
    } else if (parser.isSet(smokeOption)) {
        QTimer::singleShot(100, &application, &QCoreApplication::quit);
    }
    return application.exec();
}
