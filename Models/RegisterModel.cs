using System.ComponentModel.DataAnnotations;

namespace CrudApp.Models
{
    public class RegisterModel
{
     [Required] 
    public string? Email { get; set; }
    [Required] 
    [DataType(DataType.Password)] 
    public string? Password { get; set; }
}

}
