# Project Name : BARUSZ
BARUSZ: Blockchain security Automation and Regimentation tool Using Supervised learning and Zero-knowledge.

## Research Name : Revolutionizing Smart Contract Security: Deep Learning Techniques for Vulnerability Detection and Classification
### Background:
Smart contracts are self-executing contracts with the terms of the agreement between buyer and seller being directly written into lines of code. Ethereum smart contracts, written in Solidity, enable developers to implement complex business logic solutions on the blockchain. However, Solidity also increases the chance of bugs and code vulnerabilities that can be exploited by malicious users, leading to significant losses in digital assets.

### Objective:
The primary objective of this research project is to revolutionize smart contract security by exploring deep learning techniques, particularly Convolutional Neural Networks (CNNs), for the detection and classification of vulnerabilities in smart contracts deployed on the Ethereum main net. The project aims to provide an efficient solution to the problem of spending long hours searching for potential vulnerabilities in smart contracts.

### Methodology:
To achieve the objective, we will create a large-scale dataset of more than 100k smart contracts labeled using the Slither static analyzer, which passes the code through a number of rule-based detectors and returns a JSON file containing details about where those detectors found vulnerabilities. The 38 detectors that found a match in our dataset will be mapped to the following 5 classes: access-control, arithmetic, reentrancy, unchecked-calls, and others.

We will use deep learning techniques based on CNNs to detect and classify vulnerabilities in smart contracts. A program's executable file is transformed into a grayscale image, which is then fed into a convolutional architecture to extract relevant features and patterns. Given the similarities between a program's executable file and the bytecode of a smart contract, we investigate whether similar techniques could be useful for detecting vulnerabilities in Solidity code.

### Expected Outcome:
We expect to create a robust model capable of detecting and classifying vulnerabilities in smart contracts. The model will be trained and tested on the large-scale dataset of smart contracts, and we will provide an LSTM baseline, Conv2D models, and a Conv1D model to help users detect potential vulnerabilities in their smart contracts quickly. We will also provide error analysis to help users understand where the models may be prone to errors.

### Conclusion:
We believe that our research will help developers identify potential vulnerabilities in their smart contracts and prevent significant losses in digital assets. We plan to make our dataset and models available on the HuggingFace hub, and we encourage researchers and developers to explore them further.

