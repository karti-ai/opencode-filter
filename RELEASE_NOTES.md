# OpenCode Filter v2.0.0 Release Notes

## Major Release: World-Class Secret Protection

We're excited to announce OpenCode Filter v2.0.0 - a major upgrade that transforms the plugin into a world-class security tool for OpenCode.

## Key Highlights

### Native Visual Feedback
The biggest new feature is native OpenCode integration with visual feedback:
- Toast notifications when secrets are protected
- Status bar showing filter activity
- Command palette with /filter commands
- Dedicated panels for status and audit logs

### Comprehensive Detection
- 230 patterns covering all major services
- 8 categories: Cloud, Code Hosting, Communication, Payment, Auth, SaaS, Infrastructure, Generic
- 95.12% detection rate validated on 205 real-world examples

### Performance Verified
- <1ms processing for typical messages
- 68us average latency
- Memory efficient with LRU caching

### Easy Setup
```bash
npm install opencode-filter
npx opencode-filter init
```

## Getting Started

1. Install the plugin
2. Run the interactive wizard
3. Start OpenCode - your secrets are protected!

## Stats
- 230 patterns
- 205 test cases
- 415/416 tests passing
- 68us average latency
- 0 production dependencies

## Thanks
Thanks to the community for feedback and contributions!
