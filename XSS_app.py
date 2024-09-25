import streamlit as st
import base64
from scipy.linalg import triu
import numpy as np
import pickle
from urllib.parse import unquote
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
import nltk
nltk.download('punkt')
from nltk.tokenize import word_tokenize

st.set_page_config(page_title="XSS_Detection",page_icon="💠")

# Load your trained model
model = pickle.load(open('RandomForestClassifier_MODEL/RandomForestClassifier.sa', 'rb'))

def extract_features(line):
    line_decode = unquote(line).replace(" ", "").lower()
    features = [line_decode.count(tag) for tag in ['<link', '<object','inurl:.php?id=', '<form', '<embed', 'id=\d+&','<ilayer', '<layer', '<style', 
                                                    '<applet', '<meta', '<img', '<iframe', '<input', '<body', '<video', '<button', 
                                                    '<math', '<picture', '<map', '<svg', '<div', '<a', '<details', '<frameset', 
                                                    '<table', '<comment', '<base', '<image', 'exec', 'fromcharcode', 'eval', 
                                                    'alert', 'getelementsbytagname', 'write', 'unescape', 'escape', 'prompt', 
                                                    'onload', 'onclick', 'onerror', 'onpage', 'confirm', 'marquee', '.js', 
                                                    'javascript', '<script', '&lt;script', '%3cscript', '%3c%73%63%72%69%70%74', 
                                                    '&', '<', '>', '"', '\'', '/', '%', '*', ';', '+', '=', '%3C', 'http']]
    features.append(len(line_decode))  # length of the string
    return np.array(features)

def getVect(text):
    tagged_data = [TaggedDocument(words=word_tokenize(_d.lower()), tags=[str(i)]) for i, _d in enumerate(text)]

    max_epochs = 25
    vec_size = 20
    alpha = 0.025

    model_d2v = Doc2Vec(vector_size=vec_size, alpha=alpha, min_alpha=0.00025, min_count=1, dm=1)
    model_d2v.build_vocab(tagged_data)
    # model_d2v.save("my_model")
    
    features = [np.append(model_d2v.dv[0], extract_features(line)) for line in text]

    reshaped_features = np.array(features).reshape(len(features), -1)
    
    return reshaped_features

# Function to set the background image
def set_background_image(image_path):
    with open(image_path, "rb") as img_file:
        img_base64 = base64.b64encode(img_file.read()).decode()
        st.markdown(
            f"""
            <style>
            .stApp {{
                background-image: url('data:image/jpg;base64,{img_base64}');
                background-size: cover;
            }}
            </style>
            """,
            unsafe_allow_html=True,
        )

# Set the background image
set_background_image("Background_Image/pr.jpg")

# Page Title and Description
st.title("XSS Detection with Machine Learning")
st.write("This application detects potential XSS (Cross-Site Scripting) attacks in input text using a trained machine learning model.")

# Input Text Area
inputXSS = st.text_input("Input the line for XSS detection")
st.write("Paste or type the text you want to analyze for XSS threats in the box above.")

# Prediction Button
if st.button("Detect XSS"):
    if inputXSS:
        Xnew = getVect([inputXSS])  # Assuming getVect takes a list as input
        ynew = model.predict(Xnew)

        if ynew[0] == 1:
            st.error("Prediction: This text contains XSS!")
        else:
            st.success("Prediction: No XSS detected.")
    else:
        st.warning("Please provide input text for XSS detection.")


        

# Explanation and Footer
st.write("XSS stands for Cross-Site Scripting. An XSS attack is a type of security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.")
st.write("© 2024 CybeRSuvasH. All rights reserved.")

