project('fpp', 'cpp')
pthreads = dependency('threads')
openssl = dependency('openssl')
add_global_arguments('-std=c++17', language: 'cpp')

executable('http-client', ['http-main.cpp', 'httpreq.cpp'],
    dependencies: [pthreads, openssl])
