cmake_minimum_required(VERSION 3.30)

project(OpenProofQmlIdentityClient VERSION 1.0.0 LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Quick Network)
qt_standard_project_setup(REQUIRES 6.5)

qt_add_executable(openproof_qml_client
    main.cpp
    identityclient.cpp
    identityclient.h)

qt_add_qml_module(openproof_qml_client
    URI OpenProof.Demo
    VERSION 1.0
    QML_FILES Main.qml
    RESOURCES MaterialSymbolsRounded.ttf)

target_compile_features(openproof_qml_client PRIVATE cxx_std_20)
target_link_libraries(openproof_qml_client PRIVATE Qt6::Quick Qt6::Network)

set_target_properties(openproof_qml_client PROPERTIES
    MACOSX_BUNDLE TRUE
    MACOSX_BUNDLE_BUNDLE_NAME "OpenProof Identity Demo"
    MACOSX_BUNDLE_GUI_IDENTIFIER "dev.openproof.identity-demo")
