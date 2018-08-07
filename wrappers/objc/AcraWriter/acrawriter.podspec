Pod::Spec.new do |s|
    s.name = "acrawriter"
    s.version = "1.0.0"
    s.summary = "AcraWriter library for iOS: encrypts data into AcraStructs, allowing Acra to decrypt it"
    s.description = "Part of Acra database protection suite: developers can encrypt the sensitive data by generating AcraStructs with AcraWriter anywhere across their apps. AcraServer or AcraTranslator can be used for decryption."
    s.homepage = "https://cossacklabs.com"
    s.license = { :type => 'Apache 2.0', :file => '../../../LICENSE'}    
    s.source = { :git => "https://github.com/cossacklabs/acra.git", :tag => "#{s.version}" }
    s.author = {'cossacklabs' => 'info@cossacklabs.com'}
    
    s.dependency 'themis', '0.10.0'

    s.ios.deployment_target = '8.0'
    s.osx.deployment_target = '10.9'

    s.ios.frameworks = 'UIKit', 'Foundation', 'CoreFoundation'

    s.source_files = "AcraWriter/*.{h,m}"
    s.public_header_files = "AcraWriter/AcraWriter.h", "AcraWriter/AcraStruct.h"

    s.ios.xcconfig = { 'OTHER_CFLAGS' => '-DLIBRESSL', 'USE_HEADERMAP' => 'NO', 
        'HEADER_SEARCH_PATHS' => '"${PODS_ROOT}/themis/src" "${PODS_ROOT}/themis/src/wrappers/themis/Obj-C"', 'CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES' => 'YES' }
        
    s.osx.xcconfig = { 'OTHER_CFLAGS' => '-DLIBRESSL', 'USE_HEADERMAP' => 'NO', 
        'HEADER_SEARCH_PATHS' => '"${PODS_ROOT}/themis/src" "${PODS_ROOT}/themis/src/wrappers/themis/Obj-C"', 'CLANG_ALLOW_NON_MODULAR_INCLUDES_IN_FRAMEWORK_MODULES' => 'YES' }

end
