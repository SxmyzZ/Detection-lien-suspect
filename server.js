const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

const googleSafeBrowsingApiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
const virusTotalApiKey = process.env.VIRUS_TOTAL_API_KEY;
const phishTankApiKey = process.env.PHISH_TANK_API_KEY;

// Endpoint pour vérifier une URL
app.post('/api/check-url', async (req, res) => {
    const { url } = req.body;

    let suspicious = false;
    let reason = '';

    // Vérification heuristique basique
    if (url.includes('gov.fr') && !url.startsWith('https://www.gouv.fr')) {
        suspicious = true;
        reason = "L'URL prétend être un site gouvernemental mais n'utilise pas le domaine officiel.";
    }

    try {
        // Vérification avec Google Safe Browsing
        const safeBrowsingUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${googleSafeBrowsingApiKey}`;
        const safeBrowsingResponse = await axios.post(safeBrowsingUrl, {
            client: {
                clientId: "yourcompany",
                clientVersion: "1.5.2"
            },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [
                    { url: url }
                ]
            }
        });

        if (safeBrowsingResponse.data.matches) {
            suspicious = true;
            reason += ' L\'URL est répertoriée comme dangereuse par Google Safe Browsing.';
        }

        // Vérification avec VirusTotal
        if (virusTotalApiKey) {
            const virusTotalResponse = await checkWithVirusTotal(url, virusTotalApiKey);
            if (virusTotalResponse.malicious) {
                suspicious = true;
                reason += ' L\'URL est détectée comme malveillante par VirusTotal.';
            }
        }

        // Vérification avec PhishTank
        if (phishTankApiKey) {
            const phishTankResponse = await checkWithPhishTank(url, phishTankApiKey);
            if (phishTankResponse.phishing) {
                suspicious = true;
                reason += ' L\'URL est répertoriée comme un site de phishing par PhishTank.';
            }
        }

    } catch (error) {
        console.error('Erreur lors de la vérification des URL:', error);
        reason += ' Erreur lors de la vérification avec les APIs de sécurité.';
    }

    res.json({ suspicious, reason });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
