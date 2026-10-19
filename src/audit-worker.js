import { checkDictionary } from './crypto-tools.js?v=1.1.1';
self.onmessage = async ({ data }) => {
  try {
    const result = await checkDictionary(data.token, data.words, progress => self.postMessage({ progress }));
    self.postMessage({ result });
  } catch (error) { self.postMessage({ error: error.message }); }
};
