"use strict";

const { Helper, Model, DefaultFilteredAdapter, Filter } = require("casbin");
const { createHash } = require("crypto");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  QueryCommand,
  ScanCommand,
  PutCommand,
  DeleteCommand,
  BatchWriteCommand,
} = require("@aws-sdk/lib-dynamodb");

/**
 * Recursively finds all items in a DynamoDB table or index.
 *
 * @param {DynamoDBDocumentClient} client - The DynamoDB Document Client.
 * @param {object} params - The parameters for the DynamoDB query or scan operation.
 * @returns {Promise<Array<object>>} - The items found.
 */
const find = async (client, params) => {
  const command = params.KeyConditionExpression
    ? new QueryCommand(params)
    : new ScanCommand(params);
  const data = await client.send(command);

  if (data.LastEvaluatedKey) {
    params.ExclusiveStartKey = data.LastEvaluatedKey;
    data.Items = data.Items.concat(await find(client, params));
  }
  return data.Items;
};

/**
 * Performs a batch write operation with retries for unprocessed items.
 *
 * @param {DynamoDBDocumentClient} client - The DynamoDB Document Client.
 * @param {object} params - The parameters for the batch write operation.
 * @returns {Promise<object>} - The result of the batch write operation.
 */
const batchWrite = async (client, params) => {
  const data = await client.send(new BatchWriteCommand(params));
  if (Object.keys(data.UnprocessedItems).length) {
    params.RequestItems = data.UnprocessedItems;
    await batchWrite(client, params);
  }
  return data;
};

/**
 * Implements a policy adapter for Casbin with DynamoDB support.
 *
 * @class
 */
class CasbinDynamoDBAdapter {
  /**
   * Creates an instance of CasbinDynamoDBAdapter.
   *
   * @param {DynamoDBDocumentClient} client - The DynamoDB Document Client.
   * @param {object} opts - Options for the adapter.
   */
  constructor(client, opts = {}) {
    this.client = client;
    this.tableName = opts.tableName;
    this.hashKey = opts.hashKey;
    this.params = { TableName: opts.tableName };
    this.index = opts.index;
    if (
      opts.index &&
      opts.index.name &&
      opts.index.hashKey &&
      opts.index.hashValue
    ) {
      this.params.IndexName = opts.index.name;
      this.params.KeyConditionExpression = `#${opts.index.hashKey} = :${opts.index.hashKey}`;
      this.params.ExpressionAttributeNames = {};
      this.params.ExpressionAttributeNames[`#${opts.index.hashKey}`] =
        opts.index.hashKey;
      this.params.ExpressionAttributeValues = {};
      this.params.ExpressionAttributeValues[`:${opts.index.hashKey}`] =
        opts.index.hashValue;
    }
  }

  /**
   * Creates a new adapter instance.
   *
   * @param {DynamoDBDocumentClient} client - The DynamoDB Document Client.
   * @param {string} tableName - The name of the DynamoDB table.
   * @returns {CasbinDynamoDBAdapter} - The new adapter instance.
   */
  static async newAdapter(client, tableName) {
    return new CasbinDynamoDBAdapter(client, { tableName });
  }

  /**
   * Constructs a policy line from a policy object.
   *
   * @param {object} policy - The policy object.
   * @returns {string} - The policy line.
   */
  policyLine(policy) {
    let line = policy.pType;

    if (policy.v0) {
      line += ", " + policy.v0;
    }
    if (policy.v1) {
      line += ", " + policy.v1;
    }
    if (policy.v2) {
      line += ", " + policy.v2;
    }
    if (policy.v3) {
      line += ", " + policy.v3;
    }
    if (policy.v4) {
      line += ", " + policy.v4;
    }
    if (policy.v5) {
      line += ", " + policy.v5;
    }

    return line;
  }

  /**
   * Loads a policy line into the model.
   *
   * @param {object} policy - The policy object.
   * @param {Model} model - The Casbin model.
   */
  loadPolicyLine(policy, model) {
    const line = this.policyLine(policy);
    Helper.loadPolicyLine(line, model);
  }

  /**
   * Loads all policies from DynamoDB into the model.
   *
   * @param {Model} model - The Casbin model.
   * @returns {Promise<void>}
   */
  async loadPolicy(model) {
    const items = await find(this.client, this.params);
    for (const item of items) {
      this.loadPolicyLine(item, model);
    }
  }

  /**
   * Saves a policy line.
   *
   * @param {string} pType - The policy type.
   * @param {Array<string>} rule - The policy rule.
   * @returns {object} - The policy object.
   */
  savePolicyLine(pType, rule) {
    const [v0, v1, v2, v3, v4, v5] = rule;
    const policy = { pType, v0, v1, v2, v3, v4, v5 };
    if (this.index && this.index.hashKey && this.index.hashValue) {
      policy[this.index.hashKey] = this.index.hashValue;
    }
    policy[this.hashKey] = createHash("md5")
      .update(JSON.stringify(policy))
      .digest("hex");
    return policy;
  }

  /**
   * Saves all policies from the model into DynamoDB.
   *
   * @param {Model} model - The Casbin model.
   * @returns {Promise<boolean>}
   */
  async savePolicy(model) {
    const policyRuleAST = model.model.get("p");
    const groupingPolicyAST = model.model.get("g");

    for (const [pType, ast] of policyRuleAST) {
      for (const rule of ast.policy) {
        const casbinPolicy = this.savePolicyLine(pType, rule);
        await this.client.send(
          new PutCommand({ TableName: this.tableName, Item: casbinPolicy })
        );
      }
    }

    for (const [pType, ast] of groupingPolicyAST) {
      for (const rule of ast.policy) {
        const casbinPolicy = this.savePolicyLine(pType, rule);
        await this.client.send(
          new PutCommand({ TableName: this.tableName, Item: casbinPolicy })
        );
      }
    }

    return true;
  }

  /**
   * Adds a policy rule to DynamoDB.
   *
   * @param {string} sec - The section.
   * @param {string} pType - The policy type.
   * @param {Array<string>} rule - The policy rule.
   * @returns {Promise<void>}
   */
  async addPolicy(sec, pType, rule) {
    const policy = this.savePolicyLine(pType, rule);
    await this.client.send(
      new PutCommand({ TableName: this.tableName, Item: policy })
    );
  }

  /**
   * Removes a policy rule from DynamoDB.
   *
   * @param {string} sec - The section.
   * @param {string} pType - The policy type.
   * @param {Array<string>} rule - The policy rule.
   * @returns {Promise<void>}
   */
  async removePolicy(sec, pType, rule) {
    const policy = this.savePolicyLine(pType, rule);
    const params = { TableName: this.tableName, Key: {} };
    params.Key[this.hashKey] = policy[this.hashKey];
    await this.client.send(new DeleteCommand(params));
  }

  /**
   * Removes policy rules that match the filter from DynamoDB.
   *
   * @param {string} sec - The section.
   * @param {string} pType - The policy type.
   * @param {number} fieldIndex - The starting index of the field.
   * @param  {...string} fieldValues - The field values to filter.
   * @returns {Promise<void>}
   */
  async removeFilteredPolicy(sec, pType, fieldIndex, ...fieldValues) {
    const params = Object.assign({}, this.params);
    params.FilterExpression = "#pType = :pType";
    params.ExpressionAttributeNames = { "#pType": "pType" };
    params.ExpressionAttributeValues = { ":pType": pType };

    if (
      fieldIndex <= 0 &&
      fieldIndex + fieldValues.length > 0 &&
      !!fieldValues[0 - fieldIndex]
    ) {
      params.FilterExpression += " AND #v0 = :v0";
      params.ExpressionAttributeNames["#v0"] = "v0";
      params.ExpressionAttributeValues[":v0"] = fieldValues[0 - fieldIndex];
    }
    if (
      fieldIndex <= 1 &&
      fieldIndex + fieldValues.length > 1 &&
      !!fieldValues[1 - fieldIndex]
    ) {
      params.FilterExpression += " AND #v1 = :v1";
      params.ExpressionAttributeNames["#v1"] = "v1";
      params.ExpressionAttributeValues[":v1"] = fieldValues[1 - fieldIndex];
    }
    if (
      fieldIndex <= 2 &&
      fieldIndex + fieldValues.length > 2 &&
      !!fieldValues[2 - fieldIndex]
    ) {
      params.FilterExpression += " AND #v2 = :v2";
      params.ExpressionAttributeNames["#v2"] = "v2";
      params.ExpressionAttributeValues[":v2"] = fieldValues[2 - fieldIndex];
    }
    if (
      fieldIndex <= 3 &&
      fieldIndex + fieldValues.length > 3 &&
      !!fieldValues[3 - fieldIndex]
    ) {
      params.FilterExpression += " AND #v3 = :v3";
      params.ExpressionAttributeNames["#v3"] = "v3";
      params.ExpressionAttributeValues[":v3"] = fieldValues[3 - fieldIndex];
    }
    if (
      fieldIndex <= 4 &&
      fieldIndex + fieldValues.length > 4 &&
      !!fieldValues[4 - fieldIndex]
    ) {
      params.FilterExpression += " AND #v4 = :v4";
      params.ExpressionAttributeNames["#v4"] = "v4";
      params.ExpressionAttributeValues[":v4"] = fieldValues[4 - fieldIndex];
    }
    if (
      fieldIndex <= 5 &&
      fieldIndex + fieldValues.length > 5 &&
      !!fieldValues[5 - fieldIndex]
    ) {
      params.FilterExpression += " AND #v5 = :v5";
      params.ExpressionAttributeNames["#v5"] = "v5";
      params.ExpressionAttributeValues[":v5"] = fieldValues[5 - fieldIndex];
    }

    const items = await find(this.client, params);

    const requestItems = [];
    for (const item of items) {
      const Key = {};
      Key[this.hashKey] = item[this.hashKey];
      requestItems.push({ DeleteRequest: { Key } });
    }

    const len = Math.ceil(requestItems.length / 25);
    for (let x = 0, i = 0; x < len; i += 25, x++) {
      const params = { RequestItems: {} };
      params.RequestItems[this.tableName] = requestItems.slice(i, i + 25);
      await batchWrite(this.client, params);
    }
  }

  /**
   * Adds multiple policy rules to DynamoDB.
   *
   * @param {string} sec - The section.
   * @param {string} pType - The policy type.
   * @param {Array<Array<string>>} rules - The policy rules.
   * @returns {Promise<void>}
   */
  async addPolicies(sec, pType, rules) {
    const requestItems = [];
    for (const rule of rules) {
      const policy = this.savePolicyLine(pType, rule);
      requestItems.push({ PutRequest: { Item: policy } });
    }

    const len = Math.ceil(requestItems.length / 25);
    for (let x = 0, i = 0; x < len; i += 25, x++) {
      const params = { RequestItems: {} };
      params.RequestItems[this.tableName] = requestItems.slice(i, i + 25);
      await batchWrite(this.client, params);
    }
  }

  /**
   * Removes multiple policy rules from DynamoDB.
   *
   * @param {string} sec - The section.
   * @param {string} pType - The policy type.
   * @param {Array<Array<string>>} rules - The policy rules.
   * @returns {Promise<void>}
   */
  async removePolicies(sec, pType, rules) {
    const requestItems = [];
    for (const rule of rules) {
      const policy = this.savePolicyLine(pType, rule);
      const Key = {};
      Key[this.hashKey] = policy[this.hashKey];
      requestItems.push({ DeleteRequest: { Key } });
    }

    const len = Math.ceil(requestItems.length / 25);
    for (let x = 0, i = 0; x < len; i += 25, x++) {
      const params = { RequestItems: {} };
      params.RequestItems[this.tableName] = requestItems.slice(i, i + 25);
      await batchWrite(this.client, params);
    }
  }
}

/**
 * A filtered adapter for Casbin with DynamoDB support.
 *
 * @class
 */
class CasbinDynamoDBFilteredAdapter extends CasbinDynamoDBAdapter {
  /**
   * Creates an instance of CasbinDynamoDBFilteredAdapter.
   *
   * @param {DynamoDBDocumentClient} client - The DynamoDB Document Client.
   * @param {object} opts - Options for the adapter.
   */
  constructor(client, opts = {}) {
    super(client, opts);
    this.filtered = false;
  }

  /**
   * Loads all policies from DynamoDB into the model.
   *
   * @param {Model} model - The Casbin model.
   * @returns {Promise<void>}
   */
  async loadPolicy(model) {
    this.filtered = false;
    await super.loadPolicy(model);
  }

  /**
   * Loads filtered policies from DynamoDB into the model.
   *
   * @param {Model} model - The Casbin model.
   * @param {Filter} filter - The filter to apply.
   * @returns {Promise<void>}
   */
  async loadFilteredPolicy(model, filter) {
    if (!filter) {
      await this.loadPolicy(model);
      return;
    }

    const items = await find(this.client, this.params);
    for (const item of items) {
      const line = this.policyLine(item);

      if (!line || DefaultFilteredAdapter.filterLine(line, filter)) {
        continue;
      }

      Helper.loadPolicyLine(line, model);
    }

    this.filtered = true;
  }

  /**
   * Checks if the adapter is filtered.
   *
   * @returns {boolean} - True if filtered, else false.
   */
  isFiltered() {
    return this.filtered;
  }

  /**
   * Saves all policies from the model into DynamoDB.
   *
   * @param {Model} model - The Casbin model.
   * @returns {Promise<boolean>}
   */
  async savePolicy(model) {
    if (this.filtered) {
      throw new Error("cannot save a filtered policy");
    }
    await super.savePolicy(model);
    return true;
  }
}

module.exports = {
  CasbinDynamoDBAdapter,
  CasbinDynamoDBFilteredAdapter,
};
