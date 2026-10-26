#!/usr/bin/env python3
"""Generate the Xcode project."""
import hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def ident(name):return hashlib.sha256(name.encode()).hexdigest()[:24].upper()
def ref(name):return ident(name)
objects=[]
def add(name,body):objects.append(f'{ref(name)} = {{ {body} }};')
def quoted(s):return '"'+s.replace('"','\\"')+'"'
sets={'app':'PassportCapture','unit':'PassportCaptureTests','ui':'PassportCaptureUITests'}
for key,name in sets.items():
    files=sorted((ROOT/name).glob('*.swift'))
    for f in files:
        tag=key+'/'+f.name
        add(tag,f'isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = {quoted(f.name)}; sourceTree = "<group>";')
        add('build/'+tag,f'isa = PBXBuildFile; fileRef = {ref(tag)};')
    resources = [p for p in (ROOT/name).iterdir() if p.suffix in ('.xcassets', '.xcprivacy')] if key == 'app' else []
    for resource in resources:
        tag=key+'/'+resource.name
        kind='folder.assetcatalog' if resource.suffix == '.xcassets' else 'text.xml'
        add(tag,f'isa = PBXFileReference; lastKnownFileType = {kind}; path = {quoted(resource.name)}; sourceTree = "<group>";')
        add('build/'+tag,f'isa = PBXBuildFile; fileRef = {ref(tag)};')
    add('group/'+key,f'isa = PBXGroup; children = ({",".join(ref(key+"/"+f.name) for f in files+resources)},); path = {name}; sourceTree = "<group>";')
    add('sources/'+key,f'isa = PBXSourcesBuildPhase; buildActionMask = 2147483647; files = ({",".join(ref("build/"+key+"/"+f.name) for f in files)},); runOnlyForDeploymentPostprocessing = 0;')
    framework=ref('nfcbuild')+',' if key=='app' else ''
    add('frameworks/'+key,f'isa = PBXFrameworksBuildPhase; buildActionMask = 2147483647; files = ({framework}); runOnlyForDeploymentPostprocessing = 0;')
    add('resources/'+key,f'isa = PBXResourcesBuildPhase; buildActionMask = 2147483647; files = ({",".join(ref("build/"+key+"/"+f.name) for f in resources)}); runOnlyForDeploymentPostprocessing = 0;')
    ext='app' if key=='app' else 'xctest'
    add('product/'+key,f'isa = PBXFileReference; explicitFileType = {"wrapper.application" if key=="app" else "wrapper.cfbundle"}; path = {name}.{ext}; sourceTree = BUILT_PRODUCTS_DIR;')
    deps=''
    if key!='app':
        add('proxy/'+key,f'isa = PBXContainerItemProxy; containerPortal = {ref("project")}; proxyType = 1; remoteGlobalIDString = {ref("target/app")}; remoteInfo = PassportCapture;')
        add('dep/'+key,f'isa = PBXTargetDependency; target = {ref("target/app")}; targetProxy = {ref("proxy/"+key)};')
        deps=ref('dep/'+key)+','
    producttype={'app':'application','unit':'bundle.unit-test','ui':'bundle.ui-testing'}[key]
    packages=f'packageProductDependencies = ({ref("nfcproduct")},);' if key=='app' else ''
    add('target/'+key,f'isa = PBXNativeTarget; buildConfigurationList = {ref("configlist/"+key)}; buildPhases = ({ref("sources/"+key)},{ref("frameworks/"+key)},{ref("resources/"+key)},); buildRules = (); dependencies = ({deps}); name = {name}; {packages} productName = {name}; productReference = {ref("product/"+key)}; productType = "com.apple.product-type.{producttype}";')
    for config in ['Debug','Release']:
        settings='IPHONEOS_DEPLOYMENT_TARGET = 16.0; SDKROOT = iphoneos; SWIFT_VERSION = 5.0; CLANG_ENABLE_MODULES = YES; CODE_SIGN_STYLE = Automatic; TARGETED_DEVICE_FAMILY = 1; SUPPORTED_PLATFORMS = "iphoneos iphonesimulator"; '
        settings+=f'PRODUCT_BUNDLE_IDENTIFIER = se.openid.{name}; PRODUCT_NAME = "$(TARGET_NAME)"; '
        settings+='LD_RUNPATH_SEARCH_PATHS = "$(inherited) @executable_path/Frameworks @loader_path/Frameworks"; '
        if config=='Debug':settings+='SWIFT_OPTIMIZATION_LEVEL = "-Onone"; SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG; ENABLE_TESTABILITY = YES; DEBUG_INFORMATION_FORMAT = dwarf; ONLY_ACTIVE_ARCH = YES; '
        else:settings+='SWIFT_OPTIMIZATION_LEVEL = "-O"; DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym"; '
        if key=='app':settings+='MARKETING_VERSION = 0.2.0; CURRENT_PROJECT_VERSION = 108; ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon; INFOPLIST_FILE = PassportCapture/Info.plist; CODE_SIGN_ENTITLEMENTS = PassportCapture/PassportCapture.entitlements; '
        if key=='app':settings+=f'APP_ATTEST_ENVIRONMENT = {"development" if config == "Debug" else "production"}; '
        else:settings+='GENERATE_INFOPLIST_FILE = YES; '
        if key=='unit':settings+='TEST_HOST = "$(BUILT_PRODUCTS_DIR)/PassportCapture.app/PassportCapture"; BUNDLE_LOADER = "$(TEST_HOST)"; '
        if key=='ui':settings+='TEST_TARGET_NAME = PassportCapture; '
        add('config/'+key+'/'+config,f'isa = XCBuildConfiguration; buildSettings = {{{settings}}}; name = {config};')
    add('configlist/'+key,f'isa = XCConfigurationList; buildConfigurations = ({ref("config/"+key+"/Debug")},{ref("config/"+key+"/Release")},); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
add('rootgroup',f'isa = PBXGroup; children = ({ref("group/app")},{ref("group/unit")},{ref("group/ui")},{ref("products")},); sourceTree = "<group>";')
add('products',f'isa = PBXGroup; children = ({",".join(ref("product/"+key) for key in sets)},); name = Products; sourceTree = "<group>";')
add('nfc','isa = XCRemoteSwiftPackageReference; repositoryURL = "https://github.com/AndyQ/NFCPassportReader.git"; requirement = {kind = revision; revision = 6e37f1ab249fef82771da46d32707f2b94ed090f;};')
add('openssl','isa = XCRemoteSwiftPackageReference; repositoryURL = "https://github.com/krzyzanowskim/OpenSSL-Package.git"; requirement = {kind = exactVersion; version = 3.6.5000;};')
add('nfcproduct',f'isa = XCSwiftPackageProductDependency; package = {ref("nfc")}; productName = NFCPassportReader;')
add('nfcbuild',f'isa = PBXBuildFile; productRef = {ref("nfcproduct")};')
for config in ['Debug','Release']:add('project/'+config,f'isa = XCBuildConfiguration; buildSettings = {{}}; name = {config};')
add('projectconfig',f'isa = XCConfigurationList; buildConfigurations = ({ref("project/Debug")},{ref("project/Release")},); defaultConfigurationIsVisible = 0; defaultConfigurationName = Release;')
add('project',f'isa = PBXProject; attributes = {{LastUpgradeCheck = 1640;}}; buildConfigurationList = {ref("projectconfig")}; compatibilityVersion = "Xcode 14.0"; developmentRegion = sv; knownRegions = (sv,en,Base,); mainGroup = {ref("rootgroup")}; productRefGroup = {ref("products")}; projectDirPath = ""; projectRoot = ""; packageReferences = ({ref("nfc")},{ref("openssl")},); targets = ({",".join(ref("target/"+key) for key in sets)},);')
(ROOT/'PassportCapture.xcodeproj/project.pbxproj').write_text('// !$*UTF8*$!\n{archiveVersion = 1; classes = {}; objectVersion = 56; objects = {\n'+'\n'.join(objects)+f'\n}}; rootObject = {ref("project")};}}\n')
def buildref(key):return f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{ref("target/"+key)}" BuildableName="{sets[key]}.{ "app" if key=="app" else "xctest"}" BlueprintName="{sets[key]}" ReferencedContainer="container:PassportCapture.xcodeproj"/>'
scheme='<Scheme LastUpgradeVersion="1640" version="1.3"><BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries>'
for key in sets:scheme+=f'<BuildActionEntry buildForTesting="YES" buildForRunning="{"YES" if key=="app" else "NO"}" buildForProfiling="NO" buildForArchiving="{"YES" if key=="app" else "NO"}" buildForAnalyzing="YES">{buildref(key)}</BuildActionEntry>'
scheme+='</BuildActionEntries></BuildAction><TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables>'
for key in ['unit','ui']:scheme+=f'<TestableReference skipped="NO">{buildref(key)}</TestableReference>'
scheme+='</Testables></TestAction><LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" allowLocationSimulation="YES"><BuildableProductRunnable runnableDebuggingMode="0">'+buildref('app')+'</BuildableProductRunnable></LaunchAction><ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" savedToolIdentifier="" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES"><BuildableProductRunnable runnableDebuggingMode="0">'+buildref('app')+'</BuildableProductRunnable></ProfileAction><AnalyzeAction buildConfiguration="Debug"/><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/></Scheme>'
path=ROOT/'PassportCapture.xcodeproj/xcshareddata/xcschemes/PassportCapture.xcscheme';path.parent.mkdir(parents=True,exist_ok=True);path.write_text(scheme+'\n')
