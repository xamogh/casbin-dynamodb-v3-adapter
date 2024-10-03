# casbin-dynamodb-adapter

DynamoDB adapter for Casbin https://github.com/casbin/node-casbin

Based on [casbin-couchbase-adapter](https://github.com/MarkMYoung/casbin-couchbase-adapter).

## Installation

npm install casbin-dynamodb-adapter

## Changes in version 0.4.x

- Change in CasbinDynamoDBAdapter class import
- New CasbinDynamoDBFilteredAdapter class based on DefaultFilteredAdapter class

## Simple Example

```js
const Casbin = require('casbin');
const { CasbinDynamoDBAdapter } = require('casbin-dynamodb-adapter');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient } = require('@aws-sdk/lib-dynamodb');

const client = new DynamoDBClient({ region: 'your-region' });
const docClient = DynamoDBDocumentClient.from(client);

(async () => {
  try {
    const opts = {
      tableName: 'Test_Casbin',
      hashKey: 'id'
    };
    const adapter = new CasbinDynamoDBAdapter(docClient, opts);
    const enforcer = await Casbin.newEnforcer('model.conf', adapter);

    // Load policies from the database.
    await enforcer.loadPolicy();

    // Add a policy.
    await enforcer.addPolicy('alice', 'data1', 'read');

    // Check permissions.
    const isMatched = await enforcer.enforce('alice', 'data1', 'read');
    console.log(isMatched); // true

    // Remove a policy.
    await enforcer.removePolicy('alice', 'data1', 'read');

    // Save policies back to the database.
    await enforcer.savePolicy();

    process.exit();
  } catch (e) {
    console.error(e);
  }
})();
```