async function checkDomain() {
    var url = document.getElementById('url').value;

    try {
        const vtApiKey = '3e4d70653714855189e794b8388982c7a07cbd17d7dd0c2816bc8b77f68a662b';
        const vtUrl = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${vtApiKey}&resource=${encodeURIComponent(url)}`;
        const vtResponse = await fetch(vtUrl);
        const vtData = await vtResponse.json();

        const iqScoreApiKey = 'iNLXo3LcLDG8xmVzxRCayjBhZpMMTHQX';
        const iqScoreUrl = `https://www.ipqualityscore.com/api/json/url/iNLXo3LcLDG8xmVzxRCayjBhZpMMTHQX/${encodeURIComponent(url)}`;
        const iqScoreResponse = await fetch(iqScoreUrl);
        const iqScoreData = await iqScoreResponse.json();

        const threatIntelApiKey = 'at_aomjMRdIsfDQzObSc6p4dvTbZifjs';
        const threatIntelUrl = `https://api.threatintelligenceplatform.com/v1/infrastructureAnalysis?domainName=${encodeURIComponent(url)}&apiKey=${threatIntelApiKey}`;
        const threatIntelResponse = await fetch(threatIntelUrl);
        const threatIntelData = await threatIntelResponse.json();

        // Display the results
        displayResultsInNewPage(vtData, iqScoreData, threatIntelData);
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

function displayResultsInNewPage(vtData, iqScoreData, threatIntelligenceData) {
    var resultPage = window.open('', '_blank');
    resultPage.document.write('<html><head><title>Domain Scan Results</title></head><body>');

    // Display VirusTotal results
    resultPage.document.write('<h3>VirusTotal Information:</h3>');
    if (vtData.response_code === 1) {
        resultPage.document.write('<p>Scan results for ' + vtData.resource + ':</p>');

        // Check if the URL is considered malicious
        if (vtData.positives > 0) {
            resultPage.document.write('<p style="color: red;">This URL is considered unsafe!</p>');
        } else {
            resultPage.document.write('<p style="color: green;">This URL is safe.</p>');
        }
    } else {
        resultPage.document.write('<p>No scan results available for ' + vtData.resource + '.</p>');
    }

    // Display ipqualityscore.com WHOIS data
    resultPage.document.write('<h3>ipqualityscore.com WHOIS Information:</h3>');
    for (const key in iqScoreData) {
        resultPage.document.write('<p><strong>' + key + ':</strong> ' + iqScoreData[key] + '</p>');
    }

    // Display Threat Intelligence data
    resultPage.document.write('<h3>Threat Intelligence Information:</h3>');
    if (threatIntelligenceData && threatIntelligenceData.threats) {
        // Iterate through each threat and display relevant details
        threatIntelligenceData.threats.forEach(threat => {
            resultPage.document.write('<p><strong>Threat Type:</strong> ' + threat.type + '</p>');
            resultPage.document.write('<p><strong>Description:</strong> ' + threat.description + '</p>');
            // Add more fields as needed
        });
    } else {
        resultPage.document.write('<p>No threat intelligence information available.</p>');
    }

    resultPage.document.write('</body></html>');
    resultPage.document.close();
}
