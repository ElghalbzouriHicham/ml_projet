

import os
from flask import Flask, flash, request, redirect, url_for, render_template, jsonify
from werkzeug.utils import secure_filename
import cv2
import numpy as np
from datetime import datetime as dt
import joblib
import pefile
import pandas as pd
UPLOAD_FOLDER = 'uploads/'

ALLOWED_EXTENSIONS = {'exe'}
ALLOWED_IMAGE_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'your_secret_key'  # Set the secret key to a unique, random value

# Load the pre-trained models
try:
    model = joblib.load('pickle_image_model.pkl')  # Replace with the path to your model
    signature_model = joblib.load('pickle_signature_model.pkl')
except FileNotFoundError as e:
    print(f"Model file not found: {e}")
    exit(1)

categories = {
    0: "Adposhel",
    1: "Agent",
    2: "Allaple",
    3: "Alueron.gen!J",
    4: "Amonetize",
    5: "Androm",
    6: "Autorun",
    7: "BrowseFox",
    8: "C2LOP.gen!g",
    9: "Dialplatform.B",
    10: "Dinwod",
    11: "Elex",
    12: "Expiro",
    13: "Fakerean",
    14: "Fasong",
    15: "HackKMS",
    16: "Hlux",
    17: "Injector",
    18: "InstallCore",
    19: "Lolyda.AA1",
    20: "Lolyda.AA2",
    21: "MultiPlug",
    22: "Neoreklami",
    23: "Neshta",
    24: "non_malware",
    25: "Regrun",
    26: "Sality",
    27: "Snarasite",
    28: "Stantinko",
    29: "VBA",
    30: "VBKrypt",
    31: "Vilsel"
}

# List of categories considered as malware
malware_categories = ["Adposhel", "Agent", "Allaple", "Alueron.gen!J", "Amonetize", "Androm", "Autorun", "BrowseFox", "C2LOP.gen!g", "Dialplatform.B",
                      "Dinwod", "Elex", "Expiro", "Fakerean", "Fasong", "HackKMS", "Hlux", "Injector", "InstallCore", "Lolyda.AA1", "Lolyda.AA2", "MultiPlug", "Neoreklami",
                      "Neshta", "Regrun", "Sality", "Snarasite", "Stantinko", "VBA", "VBKrypt", "Vilsel"]


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

def preprocess_exe(file_path):
    try:
        print("Starting preprocessing for file:", file_path)
        pe = pefile.PE(file_path)
        print("PE file loaded successfully")

        # Extract general features
        features = {
            "Machine": pe.FILE_HEADER.Machine,
            "ImageBase": pe.OPTIONAL_HEADER.ImageBase,
            "Characteristics": pe.FILE_HEADER.Characteristics,
            "CheckSum": pe.OPTIONAL_HEADER.CheckSum,
            "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "SizeOfInitializedData": pe.OPTIONAL_HEADER.SizeOfInitializedData,
            "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
            "ResourcesNb": len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0,
            "MinorOperatingSystemVersion": pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            "ImportsNb": sum([len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT]) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            "SizeOfImage": pe.OPTIONAL_HEADER.SizeOfImage,
            "AddressOfEntryPoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "VersionInformationSize": len(pe.VS_VERSIONINFO[0].StringTable[0].entries) if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe.VS_VERSIONINFO[0], 'StringTable') and hasattr(pe.VS_VERSIONINFO[0].StringTable[0], 'entries') else 0
        }

       
        return pd.DataFrame([features])

    except Exception as e:
        print("Error occurred during preprocessing:", e)
        return None


@app.route('/upload_signature', methods=['POST', 'GET'])
def upload_signature():
    if request.method == 'POST':
        print("Handling POST request to /upload_signature")
        if 'file' not in request.files:
            flash('No file part')
            print("No file part")
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            print("No selected file")
            return redirect(request.url)
        print("Uploaded file:", file.filename)
        if file and allowed_file(file.filename):
            print("File allowed and saved:", file.filename)
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            print("File path:", file_path)

            df = preprocess_exe(file_path)
            if df is not None:
                prediction = signature_model.predict(df)
                print("Prediction:", prediction)
                prediction_str = str(prediction[0])
                print("Redirecting to result with prediction:", prediction_str)
                return redirect(url_for('result_sign', prediction=prediction_str))
            else:
                flash('Error occurred during preprocessing')
                print("Error occurred during preprocessing")
                return redirect(request.url)
        else:
            flash('Invalid file extension. Only .exe files are allowed.')
            print("Invalid file extension. Only .exe files are allowed.")
            return redirect(request.url)
    return render_template('index.html')

@app.route('/result_sign')
def result_sign():
    prediction = request.args.get('prediction')
    if prediction == '1':
        result_text = f"No malware detected"
    else:
        result_text = f"Malware detected"
    print("Displaying result:", prediction)
    return render_template('results_sign.html', prediction=result_text)


@app.route('/upload_file', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_image_file(file.filename):
            filename = secure_filename(file.filename)
            dt_now = dt.now().strftime("%Y%m%d%H%M%S%f")
            filename = dt_now + ".jpg"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Process the image for model prediction
            img = cv2.imread(filepath)
            if img is not None:
                img_resized = cv2.resize(img, (80, 80))  # Resize the image to 80x80 pixels
                img_array = np.array(img_resized)
                img_array = img_array.astype('float32') / 255.0  # Normalize the image data
                img_array = img_array.flatten()  # Flatten the image into a 1D array

                # Predict using the loaded model
                try:
                    prediction = model.predict([img_array])  # Put the array in a list to create a 2D array
                except Exception as e:
                    flash(f"Error during prediction: {e}")
                    return redirect(request.url)
                
                print("Prediction:", prediction)

                return redirect(url_for('result_image', prediction=prediction))
                # Check if the category is malware
            else:
                result_text = "Error processing the image"
            
            return render_template('index.html', img_path=url_for('static', filename=filepath), result=result_text)
    return render_template('index.html')
@app.route('/result_image')
def result_image():
    prediction = request.args.get('prediction')
    if prediction in malware_categories:
        result_text = f"Malware detected"
    else:
        result_text = f"No malware detected"
    print("Displaying result:", prediction)
    return render_template('results_image.html', prediction=result_text)

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(host='0.0.0.0',debug=True)