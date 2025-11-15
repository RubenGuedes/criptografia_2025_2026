
# How to Run the Q1 Solution

## Prerequisites

1.  Install the required library:
    ```bash
    pip install pycryptodome
    ```
2.  Save `gen.py`, `bob.py`, and `alice.py` in the same directory.


## Instructions

1.  **Open Terminal 1.**
2.  Generate the keys:
    ```bash
    python gen.py
    ```
3.  Start the server (it will start listening on the defined port):
    ```bash
    python bob.py
    ```
    *Output:* `Bob is listening on localhost:65432...`

4.  **Open Terminal 2.**
5.  Run the client:
    ```bash
    python alice.py
    ```

## Result

The conversation will execute in both terminals, and each will display `Conversation successful and complete.`