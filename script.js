const products = [
  { name: "Wireless Headphones", price: 2999 },
  { name: "Smart Watch", price: 4499 },
  { name: "Bluetooth Speaker", price: 1999 },
  { name: "USB-C Power Bank", price: 1499 }
];

const productList = document.getElementById("product-list");

if (productList) {
  products.forEach(product => {
    const card = document.createElement("div");
    card.className = "product";
    card.innerHTML = `
      <h3>${product.name}</h3>
      <p>₹${product.price}</p>
      <button>Add to Cart</button>
    `;
    productList.appendChild(card);
  });
=======
body {
  font-family: Arial, sans-serif;
  margin: 0;
  background: #f5f5f5;
}

header {
  background: #0d6efd;
  color: white;
  padding: 16px;
  text-align: center;
}

.product {
  background: white;
  margin: 16px;
  padding: 16px;
  border-radius: 8px;
}

button {
  background: #0d6efd;
  color: white;
  border: none;
  padding: 8px 12px;
  cursor: pointer;
  border-radius: 4px;
}