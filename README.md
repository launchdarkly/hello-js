### LaunchDarkly Sample JavaScript Application 
We've built a simple console application that demonstrates how LaunchDarkly's SDK works.  Below, you'll find the basic build procedure, but for more comprehensive instructions, you can visit your [Quickstart page](https://app.launchdarkly.com/quickstart#/) or the [JavaScript SDK reference guide](https://docs.launchdarkly.com/sdk/client-side/javascript).

#### Build instructions 

1. Edit `index.html` and set the value of `clientSideID` to your LaunchDarkly client-side ID. If there is an existing boolean feature flag in your LaunchDarkly project that you want to evaluate, set `flagKey` to the flag key.

```
const clientSideID = 'myClientSideID';
const flagKey = 'my-flag-key';
```

2. Open `index.html` in your browser.

You should receive the message "Feature flag key '<flag key>' is <true/false> for this user".
