import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand, QueryCommand, UpdateCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import { CognitoIdentityProviderClient, SignUpCommand, ConfirmSignUpCommand, InitiateAuthCommand, GetUserCommand } from '@aws-sdk/client-cognito-identity-provider';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Environment variable checks
const AWS_REGION = process.env.AWS_REGION;
const TABLE_NAME = process.env.TABLE_NAME;
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID;

if (!AWS_REGION) {
    console.error('Error: AWS_REGION environment variable is not set.');
    process.exit(1);
}
if (!TABLE_NAME) {
    console.error('Error: TABLE_NAME environment variable is not set.');
    process.exit(1);
}
if (!COGNITO_CLIENT_ID) {
    console.error('Error: COGNITO_CLIENT_ID environment variable is not set.');
    process.exit(1);
}

// AWS Clients
const client = new DynamoDBClient({ region: AWS_REGION });
const db = DynamoDBDocumentClient.from(client);
const idp = new CognitoIdentityProviderClient({ region: AWS_REGION });

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper to parse cookies
function parseCookie(cookieHeader) {
    const list = {};
    String(cookieHeader || '').split(';').forEach(function(cookie) {
        let parts = cookie.trim().split('=');
        if (parts.length > 1) {
            list[parts[0]] = parts.slice(1).join('=');
        }
    });
    return list;
}

// Middleware to require user authentication
async function requireUser(req, res, next) {
    try {
        const cookies = parseCookie(req.headers.cookie);
        const accessToken = cookies.at;

        if (!accessToken) {
            return res.status(401).json({ message: 'Authentication required' });
        }

        const command = new GetUserCommand({ AccessToken: accessToken });
        const response = await idp.send(command);

        const userAttributes = response.UserAttributes;
        let sub, email;
        for (const attr of userAttributes) {
            if (attr.Name === 'sub') {
                sub = attr.Value;
            } else if (attr.Name === 'email') {
                email = attr.Value;
            }
        }

        if (!sub || !email) {
            return res.status(401).json({ message: 'Invalid user attributes' });
        }

        req.user = { sub: sub, email: email };
        next();
    } catch (err) {
        console.error('requireUser error:', err);
        return res.status(401).json({ message: 'Authentication failed', error: err.message });
    }
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).send('ok');
});

// --- Authentication Routes ---

app.post('/auth/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const command = new SignUpCommand({
            ClientId: COGNITO_CLIENT_ID,
            Username: email,
            Password: password,
            UserAttributes: [{ Name: 'email', Value: email }]
        });
        await idp.send(command);
        res.status(200).json({ message: 'User signed up successfully. Please confirm your email.' });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(400).json({ message: err.message });
    }
});

app.post('/auth/confirm', async (req, res) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) {
            return res.status(400).json({ message: 'Email and confirmation code are required' });
        }

        const command = new ConfirmSignUpCommand({
            ClientId: COGNITO_CLIENT_ID,
            Username: email,
            ConfirmationCode: code
        });
        await idp.send(command);
        res.status(200).json({ message: 'Email confirmed successfully.' });
    } catch (err) {
        console.error('Confirm signup error:', err);
        res.status(400).json({ message: err.message });
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const command = new InitiateAuthCommand({
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: COGNITO_CLIENT_ID,
            AuthParameters: { USERNAME: email, PASSWORD: password }
        });
        const response = await idp.send(command);

        if (!response.AuthenticationResult) {
            return res.status(400).json({ message: 'Authentication failed: No result' });
        }

        res.setHeader('Set-Cookie', 'at=' + response.AuthenticationResult.AccessToken + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=3300');
        res.status(200).json({ message: 'Logged in successfully' });
    } catch (err) {
        console.error('Login error:', err);
        if (err.name === 'UserNotConfirmedException') {
            return res.status(403).json({ code: 'NOT_CONFIRMED', message: 'User not confirmed. Please confirm your email.' });
        }
        res.status(400).json({ message: err.message });
    }
});

app.post('/auth/logout', (req, res) => {
    res.setHeader('Set-Cookie', 'at=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
    res.status(200).json({ message: 'Logged out successfully' });
});

app.get('/auth/me', requireUser, (req, res) => {
    res.status(200).json({ email: req.user.email });
});

// --- Diary Entry Routes (Protected) ---

// Create a new diary entry
app.post('/entries', requireUser, async (req, res) => {
    try {
        const { title, content } = req.body;
        if (!title || !content) {
            return res.status(400).json({ message: 'Title and content are required' });
        }

        const entryId = randomUUID();
        const now = new Date().toISOString();

        const command = new PutCommand({
            TableName: TABLE_NAME,
            Item: {
                pk: 'USER#' + req.user.sub,
                sk: 'ENTRY#' + entryId,
                id: entryId,
                title: title,
                content: content,
                createdAt: now,
                updatedAt: now,
                email: req.user.email // For easier debugging/auditing, though not strictly needed for access control
            }
        });
        await db.send(command);
        res.status(201).json({ id: entryId, message: 'Entry created successfully' });
    } catch (err) {
        console.error('Create entry error:', err);
        res.status(500).json({ message: 'Failed to create entry', error: err.message });
    }
});

// Get all diary entries for the current user
app.get('/entries', requireUser, async (req, res) => {
    try {
        const command = new QueryCommand({
            TableName: TABLE_NAME,
            KeyConditionExpression: 'pk = :pkValue AND begins_with(sk, :skPrefix)',
            ExpressionAttributeValues: {
                ':pkValue': 'USER#' + req.user.sub,
                ':skPrefix': 'ENTRY#'
            }
        });
        const response = await db.send(command);
        res.status(200).json(response.Items || []);
    } catch (err) {
        console.error('Get entries error:', err);
        res.status(500).json({ message: 'Failed to retrieve entries', error: err.message });
    }
});

// Get a single diary entry by ID
app.get('/entries/:id', requireUser, async (req, res) => {
    try {
        const entryId = req.params.id;
        const command = new GetCommand({
            TableName: TABLE_NAME,
            Key: {
                pk: 'USER#' + req.user.sub,
                sk: 'ENTRY#' + entryId
            }
        });
        const response = await db.send(command);
        if (!response.Item) {
            return res.status(404).json({ message: 'Entry not found' });
        }
        res.status(200).json(response.Item);
    } catch (err) {
        console.error('Get single entry error:', err);
        res.status(500).json({ message: 'Failed to retrieve entry', error: err.message });
    }
});

// Update a diary entry
app.put('/entries/:id', requireUser, async (req, res) => {
    try {
        const entryId = req.params.id;
        const { title, content } = req.body;
        if (!title && !content) {
            return res.status(400).json({ message: 'At least title or content is required for update' });
        }

        const now = new Date().toISOString();
        let UpdateExpression = 'SET updatedAt = :updatedAt';
        const ExpressionAttributeValues = { ':updatedAt': now };

        if (title) {
            UpdateExpression += ', title = :title';
            ExpressionAttributeValues[':title'] = title;
        }
        if (content) {
            UpdateExpression += ', content = :content';
            ExpressionAttributeValues[':content'] = content;
        }

        const command = new UpdateCommand({
            TableName: TABLE_NAME,
            Key: {
                pk: 'USER#' + req.user.sub,
                sk: 'ENTRY#' + entryId
            },
            UpdateExpression: UpdateExpression,
            ExpressionAttributeValues: ExpressionAttributeValues,
            ReturnValues: 'ALL_NEW'
        });
        const response = await db.send(command);
        res.status(200).json({ message: 'Entry updated successfully', item: response.Attributes });
    } catch (err) {
        console.error('Update entry error:', err);
        res.status(500).json({ message: 'Failed to update entry', error: err.message });
    }
});

// Delete a diary entry
app.delete('/entries/:id', requireUser, async (req, res) => {
    try {
        const entryId = req.params.id;
        const command = new DeleteCommand({
            TableName: TABLE_NAME,
            Key: {
                pk: 'USER#' + req.user.sub,
                sk: 'ENTRY#' + entryId
            }
        });
        await db.send(command);
        res.status(200).json({ message: 'Entry deleted successfully' });
    } catch (err) {
        console.error('Delete entry error:', err);
        res.status(500).json({ message: 'Failed to delete entry', error: err.message });
    }
});

// Start the server
const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log('Server running on http://0.0.0.0:' + PORT);
});
