Pod::Spec.new do |s|
  s.name           = 'DeviceCrypto'
  s.version        = '0.1.1'
  s.summary        = 'Device crypto'
  s.description    = 'Device crypto for Expo using device hardware capabilities'
  s.author         = 'Piotr Pietras'
  s.homepage       = 'https://docs.expo.dev/modules/'
  s.platforms      = {
    :ios => '15.1',
    :tvos => '15.1'
  }
  s.source         = { git: '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  # Swift/Objective-C compatibility
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
  }

  s.source_files = "**/*.{h,m,mm,swift,hpp,cpp}"
end
