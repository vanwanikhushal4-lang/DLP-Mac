// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VeloxMacDLP",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "VeloxCore", targets: ["VeloxCore"]),
        .executable(name: "VeloxApp", targets: ["VeloxApp"]),
        .executable(name: "VeloxExtension", targets: ["VeloxExtension"]),
        .executable(name: "VeloxIntegrationTests", targets: ["VeloxIntegrationTests"]),
    ],
    targets: [
        .target(
            name: "VeloxCore",
            path: "Sources/VeloxCore",
            linkerSettings: [
                .linkedLibrary("EndpointSecurity")
            ]
        ),
        .executableTarget(
            name: "VeloxApp",
            dependencies: ["VeloxCore"],
            path: "Sources/VeloxApp",
            exclude: ["Info.plist", "VeloxMacDLP.entitlements"]
        ),
        .executableTarget(
            name: "VeloxExtension",
            dependencies: ["VeloxCore"],
            path: "Sources/VeloxExtension",
            exclude: ["Info.plist", "VeloxMacDLPSE.entitlements"]
        ),
        .testTarget(
            name: "VeloxCoreTests",
            dependencies: ["VeloxCore"],
            path: "Tests/VeloxCoreTests"
        ),
        .executableTarget(
            name: "VeloxIntegrationTests",
            dependencies: ["VeloxCore"],
            path: "Tests/IntegrationTests"
        ),
    ]
)
