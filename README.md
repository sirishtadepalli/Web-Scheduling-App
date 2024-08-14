For my teammates.
You must do the following to run this web application:

1. Open terminal
2. copy/paste: ``pip install mysql-connector`` or ``pip install mysql-connector-python`` for windows (I am using mac so I can not confirm this).
3. have python3 installed
4. Review all imports and make sure they are installed on your computer
5. to render css everyone needs to run: 
```npx tailwindcss -i ./static/src/css/input.css -o ./static/src/css/output.css --watch```

For css to be seen, everyone needs to run

```python3 app.py```
 . Css will not render when opening a singular html page
