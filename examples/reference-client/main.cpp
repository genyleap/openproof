#include <iostream>
#include <utility>

import openproof.examples.reference.identity;

int main()
{
    auto adapter = openproof::examples::reference::IdentityAdapter::create(
        "https://identity.example.com", "example-native",
        "http://127.0.0.1:49152/callback");
    if (!adapter) {
        std::cerr << "Unable to configure the OpenProof integration.\n";
        return 1;
    }

    auto login = adapter->beginLogin();
    if (!login) {
        std::cerr << "Unable to start the OpenProof login flow.\n";
        return 1;
    }

    std::cout << login->authorizationUrl() << '\n';
    return 0;
}
