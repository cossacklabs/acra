Pod::Spec.new do |s|
    s.name = "acrawriter"
    s.version = "1.0.3"
    s.summary = "AcraWriter library for iOS: encrypts data into AcraStructs, allowing Acra to decrypt it"
    s.description = "Part of Acra database protection suite: developers can encrypt the sensitive data by generating AcraStructs with AcraWriter anywhere across their apps. AcraServer or AcraTranslator can be used for decryption."
    s.homepage = "https://cossacklabs.com"
    
    # TODO: change on release :)
    s.source = { :git => "https://github.com/cossacklabs/acra.git", :commit => 'd289875e36a4f3be61a0f307dfa19637d45cc321'}

    s.license = { :type => 'Apache 2.0'}    
    s.author = {'cossacklabs' => 'info@cossacklabs.com'}
    
    s.dependency 'themis', '~> 0.10.4'

    s.ios.deployment_target = '8.0'
    s.osx.deployment_target = '10.9'

    s.ios.frameworks = 'UIKit', 'Foundation', 'CoreFoundation'

    s.source_files = "wrappers/objc/AcraWriter/*.{h,m}"
    s.public_header_files = "wrappers/objc/AcraWriter/AcraWriter.h", "wrappers/objc/AcraWriter/AcraStruct.h"
    
    # Enable bitcode
    s.ios.pod_target_xcconfig = {'ENABLE_BITCODE' => 'YES' }

    s.ios.xcconfig = { 'HEADER_SEARCH_PATHS' => '"${PODS_ROOT}/themis/src" "${PODS_ROOT}/themis/src/wrappers/themis/Obj-C"'}
    s.osx.xcconfig = { 'HEADER_SEARCH_PATHS' => '"${PODS_ROOT}/themis/src" "${PODS_ROOT}/themis/src/wrappers/themis/Obj-C"'}
    
end