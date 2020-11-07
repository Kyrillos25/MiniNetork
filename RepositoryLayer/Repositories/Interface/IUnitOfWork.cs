using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace RepositoryLayer.Repositories.Interface
{
    public interface IUnitOfWork
    {
        Task CompleteAsync();
    }
}
