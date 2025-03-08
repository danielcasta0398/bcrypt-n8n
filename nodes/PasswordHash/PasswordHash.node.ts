import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
} from 'n8n-workflow';

import bcrypt from 'bcryptjs';

export class PasswordHash implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Password Hash',
		name: 'passwordHash',
		icon: 'file:passwordHash.svg',
		group: ['transform'],
		version: 1,
		description: 'Hash and verify passwords using bcryptjs',
		defaults: {
			name: 'PasswordHash',
		},
		// Usamos el literal "main" pero lo casteamos para que se ajuste al tipo
		inputs: (['main'] as unknown) as (NodeConnectionType )[],
		outputs: (['main'] as unknown) as (NodeConnectionType)[],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Hash Password',
						value: 'hash',
						description: 'Generate a bcrypt hash from a password',
						action: 'Generate a bcrypt hash from a password',
					},
					{
						name: 'Verify Password',
						value: 'verify',
						description: 'Compare a password with a bcrypt hash',
						action: 'Compare a password with a bcrypt hash',
					},
				],
				default: 'hash',
				description: 'Choose an operation',
			},
			{
				displayName: 'Password',
				name: 'password',
				type: 'string',
				typeOptions: { password: true },
				default: '',
				placeholder: 'MySecretPassword',
				description: 'The password to hash or verify',
			},
			{
				displayName: 'Hash',
				name: 'hash',
				type: 'string',
				default: '',
				placeholder: '$2a$10$...',
				description: 'Bcrypt hash (only needed for verify)',
				displayOptions: {
					show: {
						operation: ['verify'],
					},
				},
			},
			{
				displayName: 'Salt Rounds',
				name: 'saltRounds',
				type: 'number',
				typeOptions: {
					minValue: 1,
					maxValue: 20,
				},
				default: 10,
				description: 'Number of salt rounds (only for hashing)',
				displayOptions: {
					show: {
						operation: ['hash'],
					},
				},
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			try {
				const operation = this.getNodeParameter('operation', i) as string;
				const password = this.getNodeParameter('password', i) as string;

				if (operation === 'hash') {
					const saltRounds = this.getNodeParameter('saltRounds', i) as number;
					const hash = await bcrypt.hash(password, saltRounds);
					returnData.push({
						json: { hash },
					});
				} else if (operation === 'verify') {
					const hash = this.getNodeParameter('hash', i) as string;
					const match = await bcrypt.compare(password, hash);
					returnData.push({
						json: { match },
					});
				}
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({ json: { error: (error as Error).message } });
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}
