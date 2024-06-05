# aiDAPal

![aidapal](https://github.com/atredispartners/aidapal/assets/17786253/a3f5a964-3f27-4f9b-8cca-ed7a3e958f77)

aiDAPal is an IDA Pro plugin that uses a locally running LLM that has been fine-tuned for Hex-Rays pseudocode to assist with code analysis. Further details about this project can be found on our blog: https://atredis.com/blog/2024/6/3/how-to-train-your-large-language-model

This repository contains the IDA Pro plugin, the associated fine-tuned weights as well as training dataset can be downloaded from Hugging Face: https://huggingface.co/AverageBusinessUser/aidapal

# Requirements / Setup
## LLM Hosting/Service
This plugin uses Ollama's API for accessing the associated LLM - https://ollama.com/

Download the fine-tuned weights and Ollama modelfile:
 - Model https://huggingface.co/AverageBusinessUser/aidapal/blob/main/aidapal-8k.Q4_K_M.gguf
 - Ollama Modelfile: https://huggingface.co/AverageBusinessUser/aidapal/blob/main/aidapal.modelfile

Configure Ollama by running the following within the directory you downloaded the weights and modelfile:
```
ollama create aidapal -f aidapal.modelfile
```

Running `ollama list` should show an entry for `aidapal` after this step:
```
% ollama list
NAME                       	ID          	SIZE  	MODIFIED
aidapal:latest             	d04d7b95027b	4.4 GB	2 months ago
```
## Python requirements
The plugin uses `requests` for HTTP requests to the API server - https://requests.readthedocs.io/en/latest/user/install/#install

By default the plugin uses the Ollama service running on the local host and is configured to use the `aidapal` weights, edit the plugin if either of these values should be different:

```python
# this list holds the list of models registered with Ollama to be accessible from the plugin.
models = ['aidapal']
# where ollama service is running
ollama_url = "http://localhost:11434/api/generate"
```

# Usage
After loading the plugin, a new context menu is accessible from the Hex-Rays window that will initiate analysis:
![image](https://github.com/atredispartners/aidapal/assets/17786253/5594b15c-6fd6-4585-b367-a076fe43ed34)

When generation is complete, a results dialog will pop up, allowing you to accept or reject the results:

![image](https://github.com/atredispartners/aidapal/assets/17786253/f27a7e55-b992-4c01-b353-f24f9bf11bd0)

Once accepted, the Hex-Rays output will be updated with your changes. A full example of this can be seen in the following screengrab:

![simple_usage](https://github.com/atredispartners/aidapal/assets/17786253/3f3845e1-3641-4f8c-9279-18368bc93e2f)

The speed of generation is going to depend on the hardware you are execting on, the above example is representative of usage on ARM (Mx) based macbooks. 







