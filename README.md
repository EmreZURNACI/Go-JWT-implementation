import Cookies from "js-cookie";

const Login = async () => {
    try {
      const res = await axios({
        method: "POST",
        url: "http://localhost:8080/signin",
        data: {
          email: "emrezurnaci@gmail.com",
          password: "123",
        },
        withCredentials: true,
        //Sunucuda bir auth işlemi falan yapıldığında geriye cokie vs dönmek istenirse bunun olması şarttır
      });
      alert(res.data);
    } catch (error) {
      alert(error);
    }
  };

  const GetProducts = async () => {
    const token = Cookies.get("Token");
    console.log(token)
    try {
      const res = await axios({
        method: "POST",
        url: "http://localhost:8080/product",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        withCredentials: true,
      });
      alert(res.data);
    } catch (error) {
      alert(error);
    }
  };
