const API_BASE_URL = 'http://localhost:5050';
const btn = document.getElementById('btnSend');
btn.addEventListener('click', async () => {
    btn.disabled = true;
    const errorBox = document.getElementById('error');
    const resultBox = document.getElementById('result');

    errorBox.style.display = 'none';
    resultBox.style.display = 'none';

    try {
        const text = document.getElementById('msg').value.trim();
        if (!text) throw new Error('Segredo vazio.');

        // 1. Gera a chave LOCALMENTE
        const keyB64 = await SecureCrypto.generateKey();

        // 2. Cifra o conteúdo
        const ciphertext = await SecureCrypto.encryptText(text, keyB64);

        // 3. Envia APENAS o blob cifrado
        const resp = await fetch(`${API_BASE_URL}/api/secrets`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                content: ciphertext,
                ttl: parseInt(document.getElementById('ttl').value, 10),
                one_time: document.getElementById('oneTime').checked
            })
        });
        if (!resp.ok) throw new Error(`Servidor: ${resp.status}`);
        const { id } = await resp.json();

        // 4. Constrói o link com a chave APÓS o # (nunca chega ao servidor)
        const url = new URL(`view.html?id=${id}#${keyB64}`, window.location.href).href;
        document.getElementById('link').value = url;
        resultBox.style.display = 'flex';
    } catch (e) {
        errorBox.textContent = `Erro: ${e.message}`;
        errorBox.style.display = 'flex';
    } finally {
        btn.disabled = false;
    }
});