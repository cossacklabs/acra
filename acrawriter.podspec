Pod::Spec.new do |s|
    s.name = "acrawriter"
    s.version = "1.0.1"
    s.summary = "AcraWriter library for iOS: encrypts data into AcraStructs, allowing Acra to decrypt it"
    s.description = "Part of Acra database protection suite: developers can encrypt the sensitive data by generating AcraStructs with AcraWriter anywhere across their apps. AcraServer or AcraTranslator can be used for decryption."
    s.homepage = "https://cossacklabs.com"
    s.source = { :git => "https://github.com/cossacklabs/acra.git", :branch => 'master'}
    s.license = { :type => 'Apache 2.0'}    
    s.author = {'cossacklabs' => 'info@cossacklabs.com'}
    
    s.dependency 'themis', '~> 0.10.0'

    s.ios.deployment_target = '8.0'
    s.osx.deployment_target = '10.9'

    s.ios.frameworks = 'UIKit', 'Foundation', 'CoreFoundation'

    s.source_files = "wrappers/objc/AcraWriter/*.{h,m}"
    s.public_header_files = "wrappers/objc/AcraWriter/AcraWriter.h", "wrappers/objc/AcraWriter/AcraStruct.h"

    s.ios.xcconfig = { 'OTHER_CFLAGS' => '-DLIBRESSL', 'USE_HEADERMAP' => 'NO', 
        'HEADER_SEARCH_PATHS' => '"${PODS_ROOT}/themis/src" "${PODS_ROOT}/themis/src/wrappers/themis/Obj-C"', 'CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES' => 'YES' }

    # Enable bitcode
    # 'bitcode-marker' directive omits bitcode payload in binary for debug builds
    s.ios.pod_target_xcconfig = {
        'OTHER_CFLAGS[config=Debug]'                => '$(inherited) -fembed-bitcode-marker',
        'OTHER_CFLAGS[config=Release]'              => '$(inherited) -fembed-bitcode',
        'BITCODE_GENERATION_MODE[config=Release]'   => 'bitcode',
        'BITCODE_GENERATION_MODE[config=Debug]'     => 'bitcode-marker'
    }
        
    s.osx.xcconfig = { 'OTHER_CFLAGS' => '-DLIBRESSL', 'USE_HEADERMAP' => 'NO', 
        'HEADER_SEARCH_PATHS' => '"${PODS_ROOT}/themis/src" "${PODS_ROOT}/themis/src/wrappers/themis/Obj-C"', 'CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES' => 'YES' }

end
